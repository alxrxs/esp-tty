/*
 * test stub: mbedtls/sha256.h -- backed by OpenSSL EVP for native tests
 *
 * Matches the mbedtls 3.x API used by ota_verify.c.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

typedef struct {
    EVP_MD_CTX *_ctx;
} mbedtls_sha256_context;

static inline void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
    ctx->_ctx = EVP_MD_CTX_new();
}
static inline void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    if (ctx->_ctx) { EVP_MD_CTX_free(ctx->_ctx); ctx->_ctx = NULL; }
}
static inline int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    (void)is224;
    return EVP_DigestInit_ex(ctx->_ctx, EVP_sha256(), NULL) ? 0 : -1;
}
static inline int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                                         const uint8_t *input, size_t ilen) {
    return EVP_DigestUpdate(ctx->_ctx, input, ilen) ? 0 : -1;
}
static inline int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, uint8_t *output) {
    unsigned int len = 32;
    return EVP_DigestFinal_ex(ctx->_ctx, output, &len) ? 0 : -1;
}
