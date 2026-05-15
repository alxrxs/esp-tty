/* Native test stub: ecc.h -- ECC P-256 backed by OpenSSL */
#pragma once
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"

#ifndef INVALID_DEVID
#define INVALID_DEVID (-2)
#endif

typedef struct {
    EC_KEY *key;  /* OpenSSL EC_KEY (P-256) */
} ecc_key;

static inline int wc_ecc_init(ecc_key *k) {
    if (!k) return -1;
    k->key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    return k->key ? 0 : -1;
}

static inline void wc_ecc_free(ecc_key *k) {
    if (k && k->key) { EC_KEY_free(k->key); k->key = NULL; }
}

static inline int wc_ecc_make_key(WC_RNG *rng, int keysize, ecc_key *k) {
    (void)rng; (void)keysize;
    if (!k || !k->key) return -1;
    return EC_KEY_generate_key(k->key) ? 0 : -1;
}

/* Export DER SubjectPublicKeyInfo */
static inline int wc_EccPublicKeyToDer(ecc_key *k, byte *out, word32 outSz, int with_algid) {
    (void)with_algid;
    if (!k || !k->key || !out) return -1;
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) return -1;
    EVP_PKEY_set1_EC_KEY(pkey, k->key);
    unsigned char *p = out;
    int len = i2d_PUBKEY(pkey, &p);
    EVP_PKEY_free(pkey);
    if (len <= 0 || (word32)len > outSz) return -1;
    return len;
}

/* Export private key DER (SEC1 ECPrivateKey wrapped in PKCS8) */
static inline int wc_EccKeyToDer(ecc_key *k, byte *out, word32 outSz) {
    if (!k || !k->key || !out) return -1;
    unsigned char *p = out;
    int len = i2d_ECPrivateKey(k->key, &p);
    if (len <= 0 || (word32)len > outSz) return -1;
    return len;
}
