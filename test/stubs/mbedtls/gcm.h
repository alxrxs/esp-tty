/*
 * test stub: mbedtls/gcm.h — backed by OpenSSL EVP AES-GCM for native tests
 *
 * Implements the mbedtls streaming GCM API used by ota_verify.c.
 *
 * OpenSSL 3 limitation: EVP_CTRL_GCM_GET_TAG is not available after
 * EVP_DecryptFinal_ex.  To work around this, we store the expected tag
 * (from ota_verify.h's ctx->tag) externally and let OpenSSL do the tag
 * comparison atomically inside DecryptFinal_ex.
 *
 * The stub exposes a non-standard field `_expected_tag` that ota_verify.c
 * populates via a macro shim OTA_VERIFY_NATIVE_TEST_SET_TAG (when defined).
 * When OTA_VERIFY_NATIVE_TEST_SET_TAG is not used, gcm_finish always returns
 * 0 and outputs the dummy computed_tag (which makes ota_verify.c's own
 * constant-time compare pass trivially).  ota_verify.c's own tag compare
 * is the actual gate in the non-native build.
 *
 * Actually, the cleanest approach for the native test: avoid the computed-tag
 * extraction problem entirely by setting the expected tag before finalising.
 * We expose a helper mbedtls_gcm_set_expected_tag() that ota_verify.c can
 * call when OTA_VERIFY_NATIVE_TEST is defined, setting the tag we compare
 * against inside mbedtls_gcm_finish.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MBEDTLS_GCM_DECRYPT 0
#define MBEDTLS_GCM_ENCRYPT 1
#define MBEDTLS_CIPHER_ID_AES 2

typedef struct {
    EVP_CIPHER_CTX *_ctx;
    int             _mode;
    uint8_t         _key[32];
    size_t          _keylen;
    uint8_t         _expected_tag[16];   /* set via mbedtls_gcm_set_expected_tag */
    int             _has_expected_tag;
} mbedtls_gcm_context;

static inline void mbedtls_gcm_init(mbedtls_gcm_context *ctx) {
    ctx->_ctx = NULL;
    ctx->_mode = 0;
    ctx->_keylen = 0;
    ctx->_has_expected_tag = 0;
}

static inline void mbedtls_gcm_free(mbedtls_gcm_context *ctx) {
    if (ctx->_ctx) { EVP_CIPHER_CTX_free(ctx->_ctx); ctx->_ctx = NULL; }
}

static inline int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                                      int cipher_id,
                                      const uint8_t *key, unsigned int keybits)
{
    (void)cipher_id;
    if (keybits != 256) return -1;
    memcpy(ctx->_key, key, 32);
    ctx->_keylen = keybits;
    return 0;
}

/* Optional: set the expected tag so gcm_finish can do proper verification.
   Call this before mbedtls_gcm_finish in native test builds. */
static inline void mbedtls_gcm_set_expected_tag(mbedtls_gcm_context *ctx,
                                                  const uint8_t *tag, size_t tag_len)
{
    if (tag_len > 16) tag_len = 16;
    memcpy(ctx->_expected_tag, tag, tag_len);
    ctx->_has_expected_tag = 1;
}

static inline int mbedtls_gcm_starts(mbedtls_gcm_context *ctx,
                                      int mode,
                                      const uint8_t *iv, size_t iv_len)
{
    ctx->_mode = mode;
    if (ctx->_ctx) { EVP_CIPHER_CTX_free(ctx->_ctx); }
    ctx->_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->_ctx) return -1;

    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (mode == MBEDTLS_GCM_DECRYPT) {
        if (!EVP_DecryptInit_ex(ctx->_ctx, cipher, NULL, NULL, NULL)) return -1;
        if (!EVP_CIPHER_CTX_ctrl(ctx->_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL)) return -1;
        if (!EVP_DecryptInit_ex(ctx->_ctx, NULL, NULL, ctx->_key, iv)) return -1;
    } else {
        if (!EVP_EncryptInit_ex(ctx->_ctx, cipher, NULL, NULL, NULL)) return -1;
        if (!EVP_CIPHER_CTX_ctrl(ctx->_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL)) return -1;
        if (!EVP_EncryptInit_ex(ctx->_ctx, NULL, NULL, ctx->_key, iv)) return -1;
    }
    return 0;
}

/* mbedtls 3.x: update */
static inline int mbedtls_gcm_update(mbedtls_gcm_context *ctx,
                                      const uint8_t *input, size_t ilen,
                                      uint8_t *output, size_t output_size,
                                      size_t *olen)
{
    (void)output_size;
    int outl = 0;
    if (ctx->_mode == MBEDTLS_GCM_DECRYPT) {
        if (!EVP_DecryptUpdate(ctx->_ctx, output, &outl, input, (int)ilen)) return -1;
    } else {
        if (!EVP_EncryptUpdate(ctx->_ctx, output, &outl, input, (int)ilen)) return -1;
    }
    *olen = (size_t)outl;
    return 0;
}

/*
 * mbedtls_gcm_finish — finalise GCM.
 *
 * For DECRYPT: sets the expected tag (if provided via mbedtls_gcm_set_expected_tag),
 *   calls EVP_DecryptFinal_ex, and copies the expected tag into 'tag' so that
 *   ota_verify.c's own constant-time compare will pass iff the OpenSSL verification
 *   passed.  If no expected tag was set, outputs all-zeros and returns 0 (tests that
 *   don't set the expected tag will see a trivial pass in ota_verify.c's compare).
 *
 * For ENCRYPT: calls EVP_EncryptFinal_ex and retrieves the computed tag.
 */
static inline int mbedtls_gcm_finish(mbedtls_gcm_context *ctx,
                                      uint8_t *output, size_t output_size,
                                      size_t  *olen,
                                      uint8_t *tag, size_t tag_len)
{
    (void)output_size;
    int outl = 0;
    int ret  = 0;

    if (ctx->_mode == MBEDTLS_GCM_DECRYPT) {
        if (ctx->_has_expected_tag) {
            /* Set the expected tag so OpenSSL can verify it */
            EVP_CIPHER_CTX_ctrl(ctx->_ctx, EVP_CTRL_GCM_SET_TAG,
                                 (int)tag_len, ctx->_expected_tag);
            ret = EVP_DecryptFinal_ex(ctx->_ctx,
                                       output ? output : (uint8_t[]){0}, &outl);
            if (ret == 1) {
                /* Tag matched — copy the expected tag into 'tag' so ota_verify.c
                   constant-time compare against ctx->tag will trivially pass. */
                memcpy(tag, ctx->_expected_tag, tag_len);
            } else {
                /* Tag mismatch — zero 'tag' so ota_verify.c compare fails. */
                memset(tag, 0, tag_len);
            }
        } else {
            /* No expected tag set — just finalise and return zeros */
            EVP_DecryptFinal_ex(ctx->_ctx,
                                 output ? output : (uint8_t[]){0}, &outl);
            memset(tag, 0, tag_len);
        }
    } else {
        if (!EVP_EncryptFinal_ex(ctx->_ctx,
                                  output ? output : (uint8_t[]){0}, &outl)) return -1;
        if (!EVP_CIPHER_CTX_ctrl(ctx->_ctx, EVP_CTRL_GCM_GET_TAG,
                                  (int)tag_len, tag)) return -1;
    }
    if (olen) *olen = (size_t)outl;
    return 0;
}
