/*
 * ota_verify.c — streaming OTA image verifier/decryptor for esp-tty
 *
 * Crypto backend (ESP-IDF 6.0 / mbedtls 4.x):
 *   Uses PSA Crypto API (psa/crypto.h).
 *   - SHA-256 (for sig)    : psa_hash_*()         → HW SHA on S3
 *   - AES-256-GCM decrypt  : psa_aead_*()          → HW AES + SW GHASH on S3
 *   - ECDSA-P256 verify    : psa_verify_hash()     → SW SP_256 on S3
 *
 * Native test build (OTA_VERIFY_NATIVE_TEST):
 *   Uses OpenSSL-backed mbedtls shims from test/stubs/mbedtls/.
 *
 * Security model (approach (b)):
 *   Stream ciphertext into OTA partition. Only call esp_ota_set_boot_partition()
 *   AFTER both ECDSA-P256 verify and GCM-tag verify pass.
 *
 * Image format:
 *   [magic 8B] [version 4B LE] [plaintext_len 4B LE] [iv 12B] [tag 16B]
 *   [ciphertext NB] [sig 64B raw r||s]
 *   Signed region: magic..end-of-ciphertext (SHA-256 → ECDSA-P256)
 */

#include "ota_verify.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

/* ── Platform selection ──────────────────────────────────────────────────── */
#ifndef OTA_VERIFY_NATIVE_TEST

/* ── Embedded: PSA Crypto ────────────────────────────────────────────────── */
#include "psa/crypto.h"
#include "esp_ota_ops.h"
#include "esp_log.h"

#define OTA_LOGE(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
#define OTA_LOGI(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)

#define OTA_USE_PSA 1

#else /* OTA_VERIFY_NATIVE_TEST */

/* ── Native: OpenSSL-backed mbedtls stubs ────────────────────────────────── */
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include <stdio.h>

#define OTA_LOGE(tag, fmt, ...) fprintf(stderr, "[%s] " fmt "\n", tag, ##__VA_ARGS__)
#define OTA_LOGI(tag, fmt, ...) fprintf(stdout, "[%s] " fmt "\n", tag, ##__VA_ARGS__)

/* Stub ESP OTA ops */
typedef uint32_t esp_ota_handle_t;
typedef struct { int dummy; } esp_partition_t;
#define ESP_OK 0
static inline const esp_partition_t *esp_ota_get_next_update_partition(void *p) {
    static esp_partition_t f; return &f;
}
static inline int esp_ota_begin(const esp_partition_t *p, size_t s, esp_ota_handle_t *h) {
    *h = 1; return 0;
}
static inline int esp_ota_write(esp_ota_handle_t h, const void *d, size_t l) { return 0; }
static inline int esp_ota_end(esp_ota_handle_t h)                              { return 0; }
static inline int esp_ota_abort(esp_ota_handle_t h)                            { return 0; }
static inline int esp_ota_set_boot_partition(const esp_partition_t *p)         { return 0; }
#define OTA_SIZE_UNKNOWN 0xFFFFFFFF

#endif /* OTA_VERIFY_NATIVE_TEST */

static const char *TAG = "ota_verify";

/* ── Image format offsets ────────────────────────────────────────────────── */
#define HDR_VERSION_OFF   8
#define HDR_PTLEN_OFF    12
#define HDR_IV_OFF       16
#define HDR_TAG_OFF      28
/* HDR_CT_OFF = 44 = OTA_HEADER_SIZE */

/* ── Context struct ──────────────────────────────────────────────────────── */
struct ota_verify_ctx {
    /* Header accumulation */
    uint8_t  hdr[OTA_HEADER_SIZE];
    size_t   hdr_bytes;
    uint32_t version;
    uint32_t plaintext_len;
    uint8_t  iv[OTA_IV_LEN];
    uint8_t  tag[OTA_TAG_LEN];

    /* Image dimensions */
    size_t   total_len;
    size_t   ct_len;
    size_t   ct_bytes_fed;

    /* Lookahead tail buffer (last OTA_SIG_LEN bytes = the signature) */
    uint8_t  tail[OTA_SIG_LEN];
    size_t   tail_len;
    uint8_t  sig[OTA_SIG_LEN];

#ifdef OTA_USE_PSA
    psa_hash_operation_t  hash_op;
    psa_aead_operation_t  aead_op;
    psa_key_id_t          aes_key_id;
    psa_key_id_t          ec_key_id;
#else
    /* Native test stubs */
    mbedtls_sha256_context sha;
    mbedtls_gcm_context    gcm;
    mbedtls_pk_context     pk;
    /* Partial GCM block (must be multiple of 16 except final) */
    uint8_t  gcm_partial[16];
    size_t   gcm_partial_len;
#endif

    esp_ota_handle_t      ota_handle;
    const esp_partition_t *ota_part;
    bool     header_done;
    bool     aborted;
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static inline uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8)
         | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

/* ── PSA public key import from PEM ──────────────────────────────────────── */
#ifdef OTA_USE_PSA

/*
 * Minimal PEM → DER base64 decoder (no external dependency).
 * Handles standard base64 alphabet; ignores whitespace.
 */
static int b64_decode(const char *src, size_t slen, uint8_t *dst, size_t dsize, size_t *olen)
{
    static const char b64chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    *olen = 0;
    uint32_t acc = 0;
    int bits = 0;
    size_t out = 0;

    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        const char *pos = strchr(b64chars, c);
        if (!pos) return -1;
        acc = (acc << 6) | (uint32_t)(pos - b64chars);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out >= dsize) return -1;
            dst[out++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    *olen = out;
    return 0;
}

/*
 * pem_to_ec_pubkey: parse PEM public key, extract raw 65-byte uncompressed
 * P-256 point (04 || x || y).
 *
 * SubjectPublicKeyInfo DER for P-256:
 *   30 59 -- SEQUENCE
 *     30 13 -- SEQUENCE (AlgorithmIdentifier)
 *       06 07 2a 86 48 ce 3d 02 01  -- OID id-ecPublicKey
 *       06 08 2a 86 48 ce 3d 03 01 07  -- OID secp256r1 / prime256v1
 *     03 42 -- BIT STRING (66 bytes)
 *       00  -- no unused bits
 *       04 xx yy...  -- uncompressed point (65 bytes)
 * Total: 2+2+9+10+2+1+65 = 91 bytes.
 * The 65-byte point starts at offset 27 (2+2+9+10+2+1+1 = 27).
 */
static int pem_extract_ec_point(const uint8_t *pem, size_t pem_len,
                                 uint8_t point_out[65])
{
    /* Find base64 payload between header and footer */
    const char *begin = "-----BEGIN PUBLIC KEY-----";
    const char *efooter = "-----END PUBLIC KEY-----";
    const char *pstr = (const char *)pem;

    const char *b64_start = strstr(pstr, begin);
    if (!b64_start) return -1;
    b64_start += strlen(begin);
    while (*b64_start == '\r' || *b64_start == '\n') b64_start++;

    const char *b64_end = strstr(b64_start, efooter);
    if (!b64_end) return -1;

    uint8_t der[128];
    size_t  der_len = 0;
    if (b64_decode(b64_start, (size_t)(b64_end - b64_start),
                   der, sizeof(der), &der_len) != 0) return -1;

    /*
     * Parse the fixed-layout SubjectPublicKeyInfo DER for P-256 (91 bytes total):
     *
     *   30 59 -- SEQUENCE (89 bytes body)
     *     30 13 -- SEQUENCE (AlgorithmIdentifier, 19 bytes)
     *       06 07 2a 86 48 ce 3d 02 01  -- OID id-ecPublicKey
     *       06 08 2a 86 48 ce 3d 03 01 07  -- OID secp256r1
     *     03 42 -- BIT STRING (66 bytes)
     *       00  -- no unused bits
     *       04 xx...  -- uncompressed EC point (65 bytes)
     *
     * Rather than scanning for the first 0x04 byte (which could hit an 0x04 in
     * the OID region), we anchor on the known fixed DER structure:
     *   - Total DER length must be exactly 91 bytes.
     *   - Byte 0..1: 30 59 (outer SEQUENCE)
     *   - Byte 22: 03 (BIT STRING tag)
     *   - Byte 23: 42 (BIT STRING length = 66)
     *   - Byte 24: 00 (no unused bits)
     *   - Byte 25: 04 (uncompressed point marker)
     *   - Bytes 25..89: the 65-byte EC point
     */
    if (der_len != 91) return -1;
    if (der[0] != 0x30 || der[1] != 0x59) return -1;  /* outer SEQUENCE */
    if (der[22] != 0x03 || der[23] != 0x42) return -1; /* BIT STRING tag+len */
    if (der[24] != 0x00) return -1;                     /* no unused bits */
    if (der[25] != 0x04) return -1;                     /* uncompressed point marker */

    memcpy(point_out, &der[25], 65);
    return 0;
}

#endif /* OTA_USE_PSA */

/* ── Context lifecycle ───────────────────────────────────────────────────── */

static void ctx_free_crypto(ota_verify_ctx_t *ctx)
{
#ifdef OTA_USE_PSA
    psa_hash_abort(&ctx->hash_op);
    psa_aead_abort(&ctx->aead_op);
    if (ctx->aes_key_id != 0) psa_destroy_key(ctx->aes_key_id);
    if (ctx->ec_key_id  != 0) psa_destroy_key(ctx->ec_key_id);
#else
    mbedtls_sha256_free(&ctx->sha);
    mbedtls_gcm_free(&ctx->gcm);
    mbedtls_pk_free(&ctx->pk);
#endif
}

ota_verify_ctx_t *ota_verify_begin(const uint8_t *pub_key_pem,
                                   size_t         pub_key_pem_len,
                                   const uint8_t  aes_key[32])
{
    if (!pub_key_pem || !aes_key || pub_key_pem_len == 0) return NULL;

    ota_verify_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

#ifdef OTA_USE_PSA
    psa_crypto_init();

    /* Import AES-256 key */
    psa_key_attributes_t aes_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&aes_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&aes_attr, 256);
    psa_set_key_usage_flags(&aes_attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&aes_attr, PSA_ALG_GCM);
    if (psa_import_key(&aes_attr, aes_key, 32, &ctx->aes_key_id) != PSA_SUCCESS) {
        OTA_LOGE(TAG, "psa_import_key (AES) failed");
        free(ctx); return NULL;
    }

    /* Extract raw 65-byte EC point from PEM */
    uint8_t ec_point[65];
    if (pem_extract_ec_point(pub_key_pem, pub_key_pem_len, ec_point) != 0) {
        OTA_LOGE(TAG, "Failed to parse EC public key from PEM");
        psa_destroy_key(ctx->aes_key_id);
        free(ctx); return NULL;
    }

    /* Import EC public key */
    psa_key_attributes_t ec_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&ec_attr,
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&ec_attr, 256);
    psa_set_key_usage_flags(&ec_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&ec_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_import_key(&ec_attr, ec_point, 65, &ctx->ec_key_id) != PSA_SUCCESS) {
        OTA_LOGE(TAG, "psa_import_key (EC) failed");
        psa_destroy_key(ctx->aes_key_id);
        free(ctx); return NULL;
    }

    /* Init SHA-256 for the signed-region hash */
    ctx->hash_op = psa_hash_operation_init();
    if (psa_hash_setup(&ctx->hash_op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        OTA_LOGE(TAG, "psa_hash_setup failed");
        psa_destroy_key(ctx->aes_key_id);
        psa_destroy_key(ctx->ec_key_id);
        free(ctx); return NULL;
    }

#else /* OTA_VERIFY_NATIVE_TEST */

    mbedtls_sha256_init(&ctx->sha);
    mbedtls_gcm_init(&ctx->gcm);
    mbedtls_pk_init(&ctx->pk);

    if (mbedtls_pk_parse_public_key(&ctx->pk, pub_key_pem, pub_key_pem_len) != 0) {
        OTA_LOGE(TAG, "mbedtls_pk_parse_public_key failed");
        goto fail_native;
    }
    if (mbedtls_pk_get_type(&ctx->pk) != MBEDTLS_PK_ECKEY) {
        OTA_LOGE(TAG, "Not an EC key");
        goto fail_native;
    }
    if (mbedtls_gcm_setkey(&ctx->gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256) != 0) {
        OTA_LOGE(TAG, "mbedtls_gcm_setkey failed");
        goto fail_native;
    }
    if (mbedtls_sha256_starts(&ctx->sha, 0) != 0) {
        OTA_LOGE(TAG, "mbedtls_sha256_starts failed");
        goto fail_native;
    }
#endif

    return ctx;

#ifdef OTA_VERIFY_NATIVE_TEST
fail_native:
    ctx_free_crypto(ctx);
    free(ctx);
    return NULL;
#endif
}

/* ── Decrypt chunk + flash write ─────────────────────────────────────────── */

static ota_verify_err_t decrypt_write(ota_verify_ctx_t *ctx,
                                       const uint8_t *ct, size_t ct_len)
{
    if (ct_len == 0) return OTA_VERIFY_OK;

#ifdef OTA_USE_PSA
    uint8_t pt_buf[512];
    while (ct_len > 0) {
        size_t take   = (ct_len < sizeof(pt_buf)) ? ct_len : sizeof(pt_buf);
        size_t pt_out = 0;
        psa_status_t s = psa_aead_update(&ctx->aead_op,
                                          ct, take, pt_buf, sizeof(pt_buf), &pt_out);
        if (s != PSA_SUCCESS) {
            OTA_LOGE(TAG, "psa_aead_update failed: %d", (int)s);
            return OTA_VERIFY_ERR_CRYPTO;
        }
        if (pt_out > 0 && esp_ota_write(ctx->ota_handle, pt_buf, pt_out) != ESP_OK)
            return OTA_VERIFY_ERR_FLASH;
        ct     += take;
        ct_len -= take;
    }

#else /* native */
    /* Feed into GCM in 16-byte blocks; keep partial block across calls */
    while (ct_len > 0) {
        size_t space = 16 - ctx->gcm_partial_len;
        size_t copy  = (ct_len < space) ? ct_len : space;
        memcpy(ctx->gcm_partial + ctx->gcm_partial_len, ct, copy);
        ctx->gcm_partial_len += copy;
        ct     += copy;
        ct_len -= copy;

        if (ctx->gcm_partial_len == 16) {
            uint8_t pt[16];
            size_t olen = 0;
            if (mbedtls_gcm_update(&ctx->gcm, ctx->gcm_partial, 16,
                                    pt, 16, &olen) != 0)
                return OTA_VERIFY_ERR_CRYPTO;
            if (olen > 0) esp_ota_write(ctx->ota_handle, pt, olen);
            ctx->gcm_partial_len = 0;
        }
    }
#endif
    return OTA_VERIFY_OK;
}

/* ── Feed ────────────────────────────────────────────────────────────────── */

ota_verify_err_t ota_verify_feed(ota_verify_ctx_t *ctx,
                                  const uint8_t    *data,
                                  size_t            len,
                                  size_t            total_image_len)
{
    if (!ctx || ctx->aborted) return OTA_VERIFY_ERR_PARAM;
    if (len == 0) return OTA_VERIFY_OK;

    /* Record total length on first call */
    if (ctx->total_len == 0) {
        /* Allow total == OTA_HEADER_SIZE + OTA_SIG_LEN (ct_len=0, pt_len=0):
         * the EMPTY_IMAGE check in the header parser will catch this and
         * return OTA_VERIFY_ERR_EMPTY_IMAGE rather than the generic TRUNCATED.
         * Anything shorter still fails as TRUNCATED (e.g. missing the sig). */
        if (total_image_len < OTA_HEADER_SIZE + OTA_SIG_LEN)
            return OTA_VERIFY_ERR_TRUNCATED;
        ctx->total_len = total_image_len;
        ctx->ct_len    = total_image_len - OTA_HEADER_SIZE - OTA_SIG_LEN;
    }

    const uint8_t *p   = data;
    size_t         rem = len;

    /* Phase 1: accumulate header */
    if (!ctx->header_done) {
        size_t need = OTA_HEADER_SIZE - ctx->hdr_bytes;
        size_t take = (rem < need) ? rem : need;
        memcpy(ctx->hdr + ctx->hdr_bytes, p, take);
        ctx->hdr_bytes += take;
        p   += take;
        rem -= take;

        if (ctx->hdr_bytes < OTA_HEADER_SIZE) return OTA_VERIFY_OK;

        /* Validate header */
        if (memcmp(ctx->hdr, OTA_MAGIC, OTA_MAGIC_LEN) != 0)
            return OTA_VERIFY_ERR_MAGIC;
        ctx->version       = le32(ctx->hdr + HDR_VERSION_OFF);
        ctx->plaintext_len = le32(ctx->hdr + HDR_PTLEN_OFF);
        if (ctx->version != OTA_VERSION)
            return OTA_VERIFY_ERR_VERSION;
        memcpy(ctx->iv,  ctx->hdr + HDR_IV_OFF,  OTA_IV_LEN);
        memcpy(ctx->tag, ctx->hdr + HDR_TAG_OFF, OTA_TAG_LEN);

        /* Reject empty image: flashing zero bytes would brick the device */
        if (ctx->plaintext_len == 0) {
            OTA_LOGE(TAG, "OTA image rejected: plaintext_len == 0 (empty firmware)");
            return OTA_VERIFY_ERR_EMPTY_IMAGE;
        }

        OTA_LOGI(TAG, "OTA header ok: v%"PRIu32" pt=%"PRIu32"B ct=%zuB",
                 ctx->version, ctx->plaintext_len, ctx->ct_len);

        /* Hash the header */
#ifdef OTA_USE_PSA
        if (psa_hash_update(&ctx->hash_op, ctx->hdr, OTA_HEADER_SIZE) != PSA_SUCCESS)
            return OTA_VERIFY_ERR_CRYPTO;
#else
        if (mbedtls_sha256_update(&ctx->sha, ctx->hdr, OTA_HEADER_SIZE) != 0)
            return OTA_VERIFY_ERR_CRYPTO;
#endif

        /* Begin OTA flash write */
        ctx->ota_part = esp_ota_get_next_update_partition(NULL);
        if (!ctx->ota_part) return OTA_VERIFY_ERR_FLASH;
        if (esp_ota_begin(ctx->ota_part, OTA_SIZE_UNKNOWN, &ctx->ota_handle) != ESP_OK)
            return OTA_VERIFY_ERR_FLASH;

#ifdef OTA_USE_PSA
        /* Set up streaming AES-256-GCM decrypt */
        ctx->aead_op = psa_aead_operation_init();
        psa_status_t s = psa_aead_decrypt_setup(&ctx->aead_op,
                                                  ctx->aes_key_id, PSA_ALG_GCM);
        if (s != PSA_SUCCESS) return OTA_VERIFY_ERR_CRYPTO;
        s = psa_aead_set_nonce(&ctx->aead_op, ctx->iv, OTA_IV_LEN);
        if (s != PSA_SUCCESS) return OTA_VERIFY_ERR_CRYPTO;
#else
        if (mbedtls_gcm_starts(&ctx->gcm, MBEDTLS_GCM_DECRYPT, ctx->iv, OTA_IV_LEN) != 0)
            return OTA_VERIFY_ERR_CRYPTO;
#endif

        ctx->header_done = true;
    }

    /* Phase 2: process ciphertext with OTA_SIG_LEN-byte lookahead */
    while (rem > 0) {
        size_t tail_space = OTA_SIG_LEN - ctx->tail_len;

        if (rem <= tail_space) {
            memcpy(ctx->tail + ctx->tail_len, p, rem);
            ctx->tail_len += rem;
            rem = 0;
        } else {
            size_t push = rem - tail_space;

            /* Push confirmed bytes from the existing tail */
            if (ctx->tail_len > 0) {
                size_t from_tail = (push < ctx->tail_len) ? push : ctx->tail_len;
#ifdef OTA_USE_PSA
                if (psa_hash_update(&ctx->hash_op, ctx->tail, from_tail) != PSA_SUCCESS)
                    return OTA_VERIFY_ERR_CRYPTO;
#else
                if (mbedtls_sha256_update(&ctx->sha, ctx->tail, from_tail) != 0)
                    return OTA_VERIFY_ERR_CRYPTO;
#endif
                ota_verify_err_t e = decrypt_write(ctx, ctx->tail, from_tail);
                if (e != OTA_VERIFY_OK) return e;
                ctx->ct_bytes_fed += from_tail;

                size_t remaining = ctx->tail_len - from_tail;
                if (remaining > 0)
                    memmove(ctx->tail, ctx->tail + from_tail, remaining);
                ctx->tail_len = remaining;
                push -= from_tail;
            }

            /* Push additional confirmed bytes directly from p */
            if (push > 0) {
#ifdef OTA_USE_PSA
                if (psa_hash_update(&ctx->hash_op, p, push) != PSA_SUCCESS)
                    return OTA_VERIFY_ERR_CRYPTO;
#else
                if (mbedtls_sha256_update(&ctx->sha, p, push) != 0)
                    return OTA_VERIFY_ERR_CRYPTO;
#endif
                ota_verify_err_t e = decrypt_write(ctx, p, push);
                if (e != OTA_VERIFY_OK) return e;
                ctx->ct_bytes_fed += push;
                p   += push;
                rem -= push;
            }

            /* Fill tail with new bytes */
            size_t fill = (rem < (size_t)OTA_SIG_LEN) ? rem : OTA_SIG_LEN;
            memcpy(ctx->tail + ctx->tail_len, p, fill);
            ctx->tail_len += fill;
            p   += fill;
            rem -= fill;
        }
    }

    return OTA_VERIFY_OK;
}

/* ── End / finalise ──────────────────────────────────────────────────────── */

ota_verify_err_t ota_verify_end(ota_verify_ctx_t *ctx)
{
    if (!ctx || ctx->aborted) return OTA_VERIFY_ERR_PARAM;

    ota_verify_err_t result = OTA_VERIFY_ERR_TRUNCATED;

    if (ctx->tail_len != OTA_SIG_LEN) {
        OTA_LOGE(TAG, "Tail has %zu bytes, expected %d", ctx->tail_len, OTA_SIG_LEN);
        goto fail;
    }
    memcpy(ctx->sig, ctx->tail, OTA_SIG_LEN);

    /* Validate that the number of ciphertext bytes actually received matches
     * the plaintext_len declared in the header.  For AES-GCM the ciphertext
     * is the same length as the plaintext, so they must agree exactly.
     * A crafted image with a wrong plaintext_len field would otherwise be
     * silently accepted. */
    if (ctx->ct_bytes_fed != (size_t)ctx->plaintext_len) {
        OTA_LOGE(TAG,
                 "Length mismatch: header says plaintext_len=%"PRIu32
                 " but received %zu ciphertext bytes",
                 ctx->plaintext_len, ctx->ct_bytes_fed);
        result = OTA_VERIFY_ERR_LENGTH_MISMATCH;
        goto fail;
    }

#ifdef OTA_USE_PSA

    /* ── Gate 1: ECDSA-P256 signature verify ────────────────────────────── */
    uint8_t digest[32];
    size_t  digest_len = 0;
    psa_status_t s = psa_hash_finish(&ctx->hash_op, digest, sizeof(digest), &digest_len);
    if (s != PSA_SUCCESS) {
        OTA_LOGE(TAG, "psa_hash_finish failed: %d", (int)s);
        result = OTA_VERIFY_ERR_CRYPTO; goto fail;
    }

    /* Convert raw r||s (64 bytes) to DER for PSA.
     * PSA_ALG_ECDSA expects: IEEE P1363 format = raw r||s (same as our format). */
    s = psa_verify_hash(ctx->ec_key_id,
                         PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                         digest, digest_len,
                         ctx->sig, OTA_SIG_LEN);
    if (s != PSA_SUCCESS) {
        OTA_LOGE(TAG, "ECDSA verify FAILED: %d", (int)s);
        result = OTA_VERIFY_ERR_SIG; goto fail;
    }
    OTA_LOGI(TAG, "ECDSA-P256 signature OK");

    /* ── Gate 2: AES-GCM tag verify (via psa_aead_verify) ───────────────── */
    /* psa_aead_verify finalises decryption and checks the GCM tag atomically */
    uint8_t final_pt[16] = {0};
    size_t  final_pt_len = 0;
    s = psa_aead_verify(&ctx->aead_op,
                         final_pt, sizeof(final_pt), &final_pt_len,
                         ctx->tag, OTA_TAG_LEN);
    if (s != PSA_SUCCESS) {
        OTA_LOGE(TAG, "AES-GCM tag verify FAILED: %d", (int)s);
        result = OTA_VERIFY_ERR_TAG; goto fail;
    }
    /* Write any final plaintext bytes (usually 0 since GCM is stream cipher) */
    if (final_pt_len > 0 && esp_ota_write(ctx->ota_handle, final_pt, final_pt_len) != ESP_OK) {
        result = OTA_VERIFY_ERR_FLASH; goto fail;
    }
    OTA_LOGI(TAG, "AES-GCM tag OK");

#else /* OTA_VERIFY_NATIVE_TEST */

    /* Flush final partial GCM block */
    if (ctx->gcm_partial_len > 0) {
        uint8_t pt[16];
        size_t  olen = 0;
        if (mbedtls_gcm_update(&ctx->gcm, ctx->gcm_partial, ctx->gcm_partial_len,
                                pt, sizeof(pt), &olen) != 0) {
            result = OTA_VERIFY_ERR_CRYPTO; goto fail;
        }
        if (olen > 0) esp_ota_write(ctx->ota_handle, pt, olen);
        ctx->gcm_partial_len = 0;
    }

    /* Finalise GCM — set expected tag so OpenSSL stub can verify atomically */
    mbedtls_gcm_set_expected_tag(&ctx->gcm, ctx->tag, OTA_TAG_LEN);
    uint8_t computed_tag[OTA_TAG_LEN];
    size_t  tag_out_len = OTA_TAG_LEN;
    if (mbedtls_gcm_finish(&ctx->gcm, NULL, 0, &tag_out_len,
                            computed_tag, OTA_TAG_LEN) != 0) {
        result = OTA_VERIFY_ERR_CRYPTO; goto fail;
    }

    /* Gate 1: ECDSA-P256 verify */
    uint8_t digest[32];
    if (mbedtls_sha256_finish(&ctx->sha, digest) != 0) {
        result = OTA_VERIFY_ERR_CRYPTO; goto fail;
    }

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);
    int ret = mbedtls_ecdsa_from_keypair(&ecdsa, mbedtls_pk_ec(ctx->pk));
    if (ret != 0) {
        mbedtls_ecdsa_free(&ecdsa);
        result = OTA_VERIFY_ERR_CRYPTO; goto fail;
    }

    mbedtls_mpi r_mpi, s_mpi;
    mbedtls_mpi_init(&r_mpi);
    mbedtls_mpi_init(&s_mpi);
    mbedtls_mpi_read_binary(&r_mpi, ctx->sig,      32);
    mbedtls_mpi_read_binary(&s_mpi, ctx->sig + 32, 32);

    ret = mbedtls_ecdsa_verify(&ecdsa.grp, digest, 32,
                                &ecdsa.Q, &r_mpi, &s_mpi);
    mbedtls_mpi_free(&r_mpi);
    mbedtls_mpi_free(&s_mpi);
    mbedtls_ecdsa_free(&ecdsa);

    if (ret != 0) {
        OTA_LOGE(TAG, "ECDSA verify FAILED: -0x%04x", -ret);
        result = OTA_VERIFY_ERR_SIG; goto fail;
    }
    OTA_LOGI(TAG, "ECDSA-P256 signature OK");

    /* Gate 2: GCM tag (already verified by mbedtls_gcm_finish via OpenSSL)
     * computed_tag was set to expected_tag on success, zeros on failure */
    uint8_t diff = 0;
    for (int i = 0; i < OTA_TAG_LEN; i++) diff |= (computed_tag[i] ^ ctx->tag[i]);
    if (diff != 0) {
        OTA_LOGE(TAG, "AES-GCM tag mismatch");
        result = OTA_VERIFY_ERR_TAG; goto fail;
    }
    OTA_LOGI(TAG, "AES-GCM tag OK");

#endif /* OTA_VERIFY_NATIVE_TEST */

    /* Commit */
    if (esp_ota_end(ctx->ota_handle) != ESP_OK) {
        result = OTA_VERIFY_ERR_FLASH; goto fail;
    }
    if (esp_ota_set_boot_partition(ctx->ota_part) != ESP_OK) {
        result = OTA_VERIFY_ERR_FLASH; goto fail;
    }
    OTA_LOGI(TAG, "OTA image accepted — reboot pending");

    ctx_free_crypto(ctx);
    free(ctx);
    return OTA_VERIFY_OK;

fail:
    esp_ota_abort(ctx->ota_handle);
    ctx_free_crypto(ctx);
    free(ctx);
    return result;
}

void ota_verify_abort(ota_verify_ctx_t *ctx)
{
    if (!ctx) return;
    if (!ctx->aborted && ctx->header_done)
        esp_ota_abort(ctx->ota_handle);
    ctx->aborted = true;
    ctx_free_crypto(ctx);
    free(ctx);
}

const char *ota_verify_strerror(ota_verify_err_t err)
{
    switch (err) {
    case OTA_VERIFY_OK:            return "OK";
    case OTA_VERIFY_ERR_MAGIC:     return "bad magic";
    case OTA_VERIFY_ERR_VERSION:   return "unsupported version";
    case OTA_VERIFY_ERR_TRUNCATED: return "image truncated";
    case OTA_VERIFY_ERR_SIG:       return "ECDSA signature invalid";
    case OTA_VERIFY_ERR_TAG:       return "AES-GCM tag mismatch";
    case OTA_VERIFY_ERR_FLASH:     return "flash write error";
    case OTA_VERIFY_ERR_OOM:       return "out of memory";
    case OTA_VERIFY_ERR_CRYPTO:    return "crypto internal error";
    case OTA_VERIFY_ERR_PARAM:           return "bad parameter";
    case OTA_VERIFY_ERR_LENGTH_MISMATCH: return "plaintext length mismatch";
    case OTA_VERIFY_ERR_EMPTY_IMAGE:     return "empty image rejected";
    default:                             return "unknown error";
    }
}
