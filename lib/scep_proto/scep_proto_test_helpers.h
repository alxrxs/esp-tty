/*
 * scep_proto_test_helpers.h -- test-only declarations for scep_proto internals
 *
 * Include this header ONLY from test code that needs to reverse-parse a
 * PKCSReq pkiMessage.  Production code must not include this file.
 *
 * The function definitions live in scep_proto.c, compiled when
 * SCEP_PROTO_TEST_HELPERS is defined.
 */

#pragma once

#include "scep_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  csr_der[SCEP_MAX_CSR_DER];
    size_t   csr_len;
    char     message_type[8];       /* e.g. "19" */
    char     transaction_id[SCEP_TRANSACTION_ID_HEX_LEN + 1];
    uint8_t  sender_nonce[SCEP_NONCE_LEN];
} scep_pkcsreq_unpacked_t;

/**
 * scep_parse_pkimessage_pkcsreq_for_test() -- reverse of scep_build_pkimessage_pkcsreq.
 *
 * Only available when scep_proto.c is compiled with SCEP_PROTO_TEST_HELPERS.
 */
int scep_parse_pkimessage_pkcsreq_for_test(const uint8_t             *p7,
                                           size_t                     p7_len,
                                           mbedtls_pk_context        *ra_priv_key,
                                           const uint8_t             *ra_cert_der,
                                           size_t                     ra_cert_len,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void                      *p_rng,
                                           scep_pkcsreq_unpacked_t   *out);

/**
 * scep_certrep_rejects_bad_sig() -- verify that scep_parse_certrep rejects
 * a CertRep whose SignedData signature byte has been flipped.
 *
 * Returns -1 if the mutation was correctly rejected (PASS),
 *          0  if scep_parse_certrep accepted the forged message (FAIL).
 *
 * Only available when scep_proto.c is compiled with SCEP_PROTO_TEST_HELPERS.
 */
int scep_certrep_rejects_bad_sig(const uint8_t      *p7,
                                 size_t              p7_len,
                                 const char         *txid,
                                 mbedtls_pk_context *recip_key,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void               *p_rng);

#ifdef __cplusplus
}
#endif
