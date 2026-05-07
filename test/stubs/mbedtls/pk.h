/*
 * test stub: mbedtls/pk.h — backed by OpenSSL for native tests
 *
 * Implements only the subset used by ota_verify.c.
 * mbedtls_pk_ec() in the real API returns a pointer to the inner keypair.
 * Here we pass ctx by pointer to avoid returning a pointer to a local copy.
 * ota_verify.c uses mbedtls_pk_ec(ctx->pk) where ctx->pk is an lvalue,
 * so we redefine mbedtls_pk_ec as a macro that takes the address.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mbedtls/ecp.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#define MBEDTLS_PK_ECKEY 3

typedef struct {
    mbedtls_ecp_keypair _kp;   /* holds the public EC_KEY pointer */
    int                 _type;
} mbedtls_pk_context;

static inline void mbedtls_pk_init(mbedtls_pk_context *ctx) {
    mbedtls_ecp_keypair_init(&ctx->_kp);
    ctx->_type = 0;
}

static inline void mbedtls_pk_free(mbedtls_pk_context *ctx) {
    mbedtls_ecp_keypair_free(&ctx->_kp);
    ctx->_type = 0;
}

static inline int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                               const uint8_t *buf, size_t buflen)
{
    /* buf is a NUL-terminated PEM string */
    BIO *bio = BIO_new_mem_buf(buf, (int)(buflen - 1)); /* skip NUL */
    if (!bio) return -1;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return -1;

    /* OpenSSL 3 compatible: use EVP_PKEY_get1_EC_KEY (deprecated but works),
       or fall back to raw EC group extraction */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
#pragma GCC diagnostic pop
    EVP_PKEY_free(pkey);
    if (!ec) return -1;

    ctx->_kp.Q._ossl_eckey = ec;   /* takes ownership */
    ctx->_type = MBEDTLS_PK_ECKEY;
    return 0;
}

static inline int mbedtls_pk_get_type(const mbedtls_pk_context *ctx) {
    return ctx->_type;
}

/*
 * mbedtls_pk_ec: return pointer to the inner keypair.
 * Real mbedtls takes ctx by value; our stub takes it by pointer to avoid
 * returning pointer to a local copy.
 * We use a macro so ota_verify.c's mbedtls_pk_ec(ctx->pk) becomes
 * _mbedtls_pk_ec_ptr(&(ctx->pk)), which is safe.
 */
static inline mbedtls_ecp_keypair *_mbedtls_pk_ec_ptr(mbedtls_pk_context *ctx) {
    return &ctx->_kp;
}
#define mbedtls_pk_ec(pk_ctx) _mbedtls_pk_ec_ptr(&(pk_ctx))
