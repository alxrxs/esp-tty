/* Native test stub: rsa.h -- RSA-2048 backed by OpenSSL */
#pragma once
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#ifndef INVALID_DEVID
#define INVALID_DEVID (-2)
#endif

#ifndef RSAk
#define RSAk  645  /* wolfSSL oid_sum.h: RSA key OID sum */
#endif

typedef struct {
    EVP_PKEY *pkey;  /* OpenSSL EVP_PKEY wrapping RSA-2048 */
} RsaKey;

static inline int wc_InitRsaKey(RsaKey *k, void *heap) {
    (void)heap;
    if (!k) return -1;
    k->pkey = NULL;
    return 0;
}

static inline void wc_FreeRsaKey(RsaKey *k) {
    if (k && k->pkey) { EVP_PKEY_free(k->pkey); k->pkey = NULL; }
}

static inline int wc_MakeRsaKey(RsaKey *k, int size, long e, WC_RNG *rng) {
    (void)rng;
    if (!k) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, size) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    BIGNUM *bn = BN_new(); BN_set_word(bn, (unsigned long)e);
    /* Set public exponent -- EVP API varies; use RSA_generate_key as fallback */
    EVP_PKEY_CTX_free(ctx);
    BN_free(bn);
    RSA *rsa = RSA_generate_key((int)size, (unsigned long)e, NULL, NULL);
    if (!rsa) return -1;
    k->pkey = EVP_PKEY_new();
    if (!k->pkey) { RSA_free(rsa); return -1; }
    if (!EVP_PKEY_assign_RSA(k->pkey, rsa)) {
        EVP_PKEY_free(k->pkey); k->pkey = NULL; RSA_free(rsa); return -1;
    }
    return 0;
}

/* Export SubjectPublicKeyInfo DER (RSA public key) */
static inline int wc_RsaKeyToPublicDer(RsaKey *k, byte *out, word32 outSz) {
    if (!k || !k->pkey || !out) return -1;
    unsigned char *p = out;
    int len = i2d_PUBKEY(k->pkey, &p);
    if (len <= 0 || (word32)len > outSz) return -1;
    return len;
}

/* Export RSA private key to DER (traditional RSAPrivateKey format) */
static inline int wc_RsaKeyToDer(RsaKey *k, byte *out, word32 outSz) {
    if (!k || !k->pkey || !out) return -1;
    RSA *rsa = EVP_PKEY_get0_RSA(k->pkey);
    if (!rsa) return -1;
    unsigned char *p = out;
    int len = i2d_RSAPrivateKey(rsa, &p);
    if (len <= 0 || (word32)len > outSz) return -1;
    return len;
}

/* Decode RSA private key from DER */
static inline int wc_RsaPrivateKeyDecode(const byte *input, word32 *inOutIdx,
                                          RsaKey *key, word32 inSz) {
    if (!input || !key) return -1;
    const unsigned char *p = input + (*inOutIdx);
    long len = (long)(inSz - *inOutIdx);
    RSA *rsa = d2i_RSAPrivateKey(NULL, &p, len);
    if (!rsa) return -1;
    key->pkey = EVP_PKEY_new();
    if (!key->pkey) { RSA_free(rsa); return -1; }
    if (!EVP_PKEY_assign_RSA(key->pkey, rsa)) {
        EVP_PKEY_free(key->pkey); key->pkey = NULL; RSA_free(rsa); return -1;
    }
    *inOutIdx = inSz;
    return 0;
}
