/*
 * pubkey_auth.c -- OpenSSH public key parsing and hash-based auth
 */

#include "pubkey_auth.h"

#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/coding.h"

#include "esp_log.h"

static const char *TAG = "pubkey_auth";

bool pubkey_parse_b64(const char *openssh_line,
                      const char **b64_start, size_t *b64_len)
{
    if (!openssh_line || !b64_start || !b64_len) return false;

    /* Skip key-type token ("ssh-ed25519 ", "ecdsa-sha2-nistp256 ", ...) */
    const char *p = openssh_line;
    while (*p && *p != ' ') p++;
    if (*p != ' ') return false;
    p++;  /* skip the space */

    /* Base64 field runs until next space or end-of-string */
    const char *start = p;
    while (*p && *p != ' ' && *p != '\n' && *p != '\r') p++;
    size_t len = (size_t)(p - start);
    if (len == 0) return false;

    *b64_start = start;
    *b64_len   = len;
    return true;
}

bool pubkey_compute_hash(const char *openssh_line,
                         uint8_t hash_out[PUBKEY_HASH_SIZE])
{
    const char *b64_start;
    size_t      b64_len;

    if (!pubkey_parse_b64(openssh_line, &b64_start, &b64_len)) {
        ESP_LOGE(TAG, "pubkey_compute_hash: malformed pubkey string");
        return false;
    }

    /* 1024 bytes accommodates RSA-4096 SSH public key blobs (~800 B decoded).
     * RSA-2048 is ~400 B, Ed25519/ECDSA are ~100 B.  Keys requiring more than
     * 1024 B will fail Base64_Decode (buffer-too-small) and return false with
     * a log message rather than silently succeeding. */
    uint8_t blob[1024];
    word32  blob_sz = sizeof(blob);
    if (Base64_Decode((const byte *)b64_start, (word32)b64_len,
                      blob, &blob_sz) != 0) {
        ESP_LOGE(TAG, "pubkey_compute_hash: base64 decode failed "
                      "(key blob may exceed 1024-byte limit)");
        return false;
    }

    /* SHA-256( uint32be(blob_len) || blob ) */
    Sha256  sha;
    uint8_t len_buf[4];
    len_buf[0] = (blob_sz >> 24) & 0xFF;
    len_buf[1] = (blob_sz >> 16) & 0xFF;
    len_buf[2] = (blob_sz >>  8) & 0xFF;
    len_buf[3] = (blob_sz      ) & 0xFF;

    /* Every wolfCrypt SHA-256 call can fail (e.g. ESP32 HW-accel busy/timeout).
     * On any failure hash_out is left indeterminate, so we must not report
     * success -- callers compare this hash for authentication.  Free the ctx
     * and return false so the caller treats it as "no usable hash". */
    int ret = wc_InitSha256(&sha);
    if (ret != 0) {
        ESP_LOGE(TAG, "pubkey_compute_hash: wc_InitSha256 failed: %d", ret);
        return false;
    }
    ret = wc_Sha256Update(&sha, len_buf, 4);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, blob, blob_sz);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, hash_out);
    if (ret != 0) {
        ESP_LOGE(TAG, "pubkey_compute_hash: SHA-256 failed: %d", ret);
        wc_Sha256Free(&sha);
        return false;
    }

    wc_Sha256Free(&sha);
    return true;
}

pubkey_auth_result_t pubkey_auth_check(
    const uint8_t *presented_key, size_t presented_key_sz,
    const uint8_t  expected_hash[PUBKEY_HASH_SIZE])
{
    if (!presented_key || presented_key_sz == 0)
        return PUBKEY_AUTH_REJECTED;
    if (!expected_hash)
        return PUBKEY_AUTH_REJECTED;

    /* Compute SHA-256( uint32be(presented_key_sz) || presented_key ) */
    Sha256  sha;
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    uint8_t len_buf[4];
    uint32_t sz32 = (uint32_t)presented_key_sz;
    len_buf[0] = (sz32 >> 24) & 0xFF;
    len_buf[1] = (sz32 >> 16) & 0xFF;
    len_buf[2] = (sz32 >>  8) & 0xFF;
    len_buf[3] = (sz32      ) & 0xFF;

    /*
     * Check every SHA-256 return code.  A wolfCrypt SHA call can fail (ESP32
     * HW-accel busy/timeout, SW-path allocation failure).  On failure digest[]
     * is indeterminate; comparing it constant-time against expected_hash could
     * spuriously match (mis-auth) or, worse, leak nothing useful while still
     * authenticating.  Treat ANY SHA failure as authentication REJECTED and
     * free the ctx.  We do not branch on the *value* of the hash here, only on
     * the success/failure of the digest operation, so this does not weaken the
     * constant-time guarantee of the comparison below. */
    int ret = wc_InitSha256(&sha);
    if (ret != 0)
        return PUBKEY_AUTH_REJECTED;
    ret = wc_Sha256Update(&sha, len_buf, 4);
    if (ret == 0)
        ret = wc_Sha256Update(&sha, presented_key, (word32)presented_key_sz);
    if (ret == 0)
        ret = wc_Sha256Final(&sha, digest);
    if (ret != 0) {
        wc_Sha256Free(&sha);
        return PUBKEY_AUTH_REJECTED;
    }
    wc_Sha256Free(&sha);

    /*
     * Constant-time comparison: accumulate XOR differences through a volatile
     * aggregator so the compiler cannot short-circuit the loop.  Do not use
     * memcmp() -- it may return early on the first differing byte, leaking
     * timing information about the expected hash.
     *
     * wolfSSL ships ConstantCompare() (wolfssl/wolfcrypt/misc.h) which is also
     * timing-safe, but its definition lives in wolfcrypt/src/misc.c, which this
     * firmware EXCLUDES from the wolfSSL build (see the COMPONENT_SRCEXCLUDE
     * list and the matching ForceZero workaround in main/host_key.c).  Calling
     * it from this application TU would be an unresolved external symbol at
     * link time, so we keep the hardened local loop instead.  (SSH-F2)
     */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < PUBKEY_HASH_SIZE; i++)
        diff |= (uint8_t)(digest[i] ^ expected_hash[i]);

    /* Reduce the volatile accumulator to a 0/1 mask without a data-dependent
     * branch, then map to the result enum.  Reading `diff` once into a local
     * keeps the comparison itself off the volatile object. */
    uint8_t d = diff;
    return (d == 0) ? PUBKEY_AUTH_OK : PUBKEY_AUTH_REJECTED;
}

pubkey_user_class_t pubkey_classify_user(const char *username, size_t username_sz)
{
    if (!username || username_sz == 0)
        return PUBKEY_USER_REJECTED;

    if (username_sz == 3 &&
        username[0] == 'o' && username[1] == 't' && username[2] == 'a')
        return PUBKEY_USER_OTA;

    if (username_sz == 3 &&
        username[0] == 't' && username[1] == 't' && username[2] == 'y')
        return PUBKEY_USER_TTY;

    return PUBKEY_USER_REJECTED;
}

char *format_fingerprint(const uint8_t digest[PUBKEY_HASH_SIZE],
                         char *out, size_t out_sz)
{
    /* Each byte needs "xx:" (3 chars), last byte needs "xx\0" (3 chars too) */
    if (!digest || !out || out_sz < (size_t)(PUBKEY_HASH_SIZE * 3)) return NULL;

    for (int i = 0; i < PUBKEY_HASH_SIZE; i++) {
        snprintf(out + i * 3, 4, "%02x%s",
                 digest[i], (i < PUBKEY_HASH_SIZE - 1) ? ":" : "");
    }
    return out;
}
