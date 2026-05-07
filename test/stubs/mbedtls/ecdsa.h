/*
 * test stub: mbedtls/ecdsa.h — backed by OpenSSL EC + ECDSA for native tests
 *
 * Only the subset used by ota_verify.c is implemented.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mbedtls/ecp.h"   /* mbedtls_ecp_keypair, mbedtls_mpi */
#include "mbedtls/pk.h"    /* mbedtls_pk_context, mbedtls_pk_ec macro */

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/* ecdsa context = ecp keypair */
typedef mbedtls_ecp_keypair mbedtls_ecdsa_context;

static inline void mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx) {
    mbedtls_ecp_keypair_init(ctx);
}
static inline void mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx) {
    mbedtls_ecp_keypair_free(ctx);
}

/*
 * from_keypair: copy the EC_KEY reference from src into dst.
 * We increment the refcount so both src and dst can free independently.
 */
static inline int mbedtls_ecdsa_from_keypair(mbedtls_ecdsa_context *dst,
                                              const mbedtls_ecp_keypair *src)
{
    if (!src || !src->Q._ossl_eckey) return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    /* EC_KEY_up_ref increments refcount so both copies can free */
    EC_KEY_up_ref(src->Q._ossl_eckey);
#pragma GCC diagnostic pop
    dst->Q._ossl_eckey = src->Q._ossl_eckey;
    return 0;
}

/*
 * mbedtls_ecdsa_verify — verify raw r,s against digest using OpenSSL.
 * The EC_KEY is stored in Q._ossl_eckey (set by from_keypair).
 */
static inline int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                                        const unsigned char *hash, size_t hlen,
                                        const mbedtls_ecp_point *Q,
                                        const mbedtls_mpi *r,
                                        const mbedtls_mpi *s)
{
    (void)grp;
    EC_KEY *ec_key = Q->_ossl_eckey;
    if (!ec_key) return -1;

    /* Build ECDSA_SIG from r and s MPIs */
    BIGNUM *bn_r = BN_dup(r->_bn);
    BIGNUM *bn_s = BN_dup(s->_bn);
    if (!bn_r || !bn_s) { BN_free(bn_r); BN_free(bn_s); return -1; }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) { BN_free(bn_r); BN_free(bn_s); return -1; }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ECDSA_SIG_set0(sig, bn_r, bn_s); /* takes ownership of bn_r, bn_s */
    int ok = ECDSA_do_verify(hash, (int)hlen, sig, ec_key);
#pragma GCC diagnostic pop
    ECDSA_SIG_free(sig);
    return (ok == 1) ? 0 : -0x4c00; /* MBEDTLS_ERR_ECP_VERIFY_FAILED */
}
