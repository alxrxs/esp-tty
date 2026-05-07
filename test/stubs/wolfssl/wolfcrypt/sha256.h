/* Native test stub: sha256.h backed by OpenSSL EVP (OpenSSL 3 compatible) */
#pragma once
#include <openssl/evp.h>
#include <stdlib.h>
#include "wolfssl/wolfcrypt/settings.h"

#define WC_SHA256_DIGEST_SIZE 32

typedef struct { EVP_MD_CTX *ctx; } Sha256;

static inline int wc_InitSha256(Sha256 *s) {
    s->ctx = EVP_MD_CTX_new();
    if (!s->ctx) return -1;
    EVP_DigestInit_ex(s->ctx, EVP_sha256(), NULL);
    return 0;
}
static inline int wc_Sha256Update(Sha256 *s, const byte *d, word32 n) {
    EVP_DigestUpdate(s->ctx, d, n);
    return 0;
}
static inline int wc_Sha256Final(Sha256 *s, byte *out) {
    unsigned int len = WC_SHA256_DIGEST_SIZE;
    EVP_DigestFinal_ex(s->ctx, out, &len);
    EVP_MD_CTX_free(s->ctx);
    s->ctx = NULL;
    return 0;
}
