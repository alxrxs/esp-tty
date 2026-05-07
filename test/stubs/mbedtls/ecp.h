/*
 * test stub: mbedtls/ecp.h — backed by OpenSSL EC for native tests
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

/* MPI backed by OpenSSL BIGNUM */
typedef struct {
    BIGNUM *_bn;
} mbedtls_mpi;

static inline void mbedtls_mpi_init(mbedtls_mpi *x)      { x->_bn = BN_new(); }
static inline void mbedtls_mpi_free(mbedtls_mpi *x)      { BN_free(x->_bn); x->_bn = NULL; }
static inline int  mbedtls_mpi_read_binary(mbedtls_mpi *x,
                                            const unsigned char *buf, size_t buflen) {
    x->_bn = BN_bin2bn(buf, (int)buflen, x->_bn);
    return x->_bn ? 0 : -1;
}

/* ECP point — wraps an OpenSSL EC_KEY (public key only for verify) */
typedef struct {
    EC_KEY *_ossl_eckey;   /* set by pk.h stub when parsing public key */
} mbedtls_ecp_point;

static inline void mbedtls_ecp_point_init(mbedtls_ecp_point *p) { p->_ossl_eckey = NULL; }
static inline void mbedtls_ecp_point_free(mbedtls_ecp_point *p) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    EC_KEY_free(p->_ossl_eckey);
#pragma GCC diagnostic pop
    p->_ossl_eckey = NULL;
}

/* ECP group — not used in native test verify path */
typedef struct { int dummy; } mbedtls_ecp_group;
static inline void mbedtls_ecp_group_init(mbedtls_ecp_group *g) { (void)g; }
static inline void mbedtls_ecp_group_free(mbedtls_ecp_group *g) { (void)g; }

/* ECP keypair */
typedef struct {
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;   /* private key (unused in verify) */
    mbedtls_ecp_point Q;   /* public key */
} mbedtls_ecp_keypair;

static inline void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *kp) {
    mbedtls_ecp_group_init(&kp->grp);
    mbedtls_mpi_init(&kp->d);
    mbedtls_ecp_point_init(&kp->Q);
}
static inline void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *kp) {
    mbedtls_ecp_group_free(&kp->grp);
    mbedtls_mpi_free(&kp->d);
    mbedtls_ecp_point_free(&kp->Q);
}
