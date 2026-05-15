/*
 * scep_proto.h -- SCEP (RFC 8894) wire-protocol primitives for esp-tty
 *
 * Pure C, no ESP-IDF, no network I/O.  Compiled against mbedTLS on-device
 * and against system mbedTLS for native unit tests.
 *
 * Target CA: Microsoft NDES (mscep.dll) in legacy CryptoAPI/CSP mode.
 *
 * Key algorithm: RSA-2048 with SHA-256 (PKCS#1 v1.5 signing).
 * Rationale: NDES in legacy mode cannot verify ECDSA-signed pkiMessages;
 * it returns failInfo=1 (badMessageCheck) for any non-RSA signer.
 * Confirmed end-to-end: RSA-2048 succeeds, ECDSA P-256 fails (RFC 8894 §3.5.2).
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* mbedTLS types used in public API.
 * On-device: ESP-IDF ships full mbedTLS (components/mbedtls).
 * Native tests: system mbedTLS (apt install libmbedtls-dev). */
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define SCEP_TRANSACTION_ID_HEX_LEN  64   /* hex(SHA-256) = 32 bytes => 64 chars + NUL */
#define SCEP_NONCE_LEN               16   /* RFC 8894 §3.1 senderNonce / recipientNonce */

#define SCEP_MAX_CSR_DER             2048 /* max DER bytes for an RSA-2048 CSR */
#define SCEP_MAX_P7_LEN              8192 /* max pkiMessage output size */
#define SCEP_MAX_CERT_DER            2048 /* max DER bytes for a leaf cert */
#define SCEP_MAX_CA_BUNDLE_CERT_DER  4096 /* max DER per cert in CA bundle */

/* -----------------------------------------------------------------------
 * Subject fields for CSR generation (RFC 8894 §2 / X.520)
 * --------------------------------------------------------------------- */

typedef struct {
    const char *common_name;        /* CN  (required) */
    const char *organization;       /* O   (optional, may be NULL) */
    const char *organizational_unit;/* OU  (optional, may be NULL) */
    const char *country;            /* C   (optional, may be NULL, 2-char ISO) */
    const char *state;              /* ST  (optional, may be NULL) */
    const char *locality;           /* L   (optional, may be NULL) */
} scep_subject_t;

/* -----------------------------------------------------------------------
 * pkiStatus values (RFC 8894 §3.3)
 * --------------------------------------------------------------------- */

typedef enum {
    SCEP_PKI_STATUS_SUCCESS  = 0,   /* certificate issued */
    SCEP_PKI_STATUS_FAILURE  = 2,   /* request rejected */
    SCEP_PKI_STATUS_PENDING  = 3,   /* request in manual queue */
    SCEP_PKI_STATUS_UNKNOWN  = -1,  /* not yet parsed / absent */
} scep_pki_status_t;

/* -----------------------------------------------------------------------
 * failInfo values (RFC 8894 §3.3)
 * --------------------------------------------------------------------- */

typedef enum {
    SCEP_FAIL_INFO_BAD_ALG            = 0,
    SCEP_FAIL_INFO_BAD_MESSAGE_CHECK  = 1,
    SCEP_FAIL_INFO_BAD_REQUEST        = 2,
    SCEP_FAIL_INFO_BAD_TIME           = 3,
    SCEP_FAIL_INFO_BAD_CERT_ID        = 4,
    SCEP_FAIL_INFO_NONE               = -1, /* absent from response */
} scep_fail_info_t;

/* -----------------------------------------------------------------------
 * CA / RA certificate bundle (from GetCACert response)
 * RFC 8894 §4.1: response is a PKCS#7 degenerate SignedData.
 * --------------------------------------------------------------------- */

typedef struct {
    /*
     * Each pointer below is valid only for the lifetime of the p7 buffer
     * passed to scep_parse_getcacert().  Copy if needed beyond that.
     */
    const uint8_t *ca_cert_der;         /* Root / issuing CA cert DER */
    size_t         ca_cert_len;
    const uint8_t *ra_sign_cert_der;    /* RA signing cert DER (may == ra_encrypt_cert_der) */
    size_t         ra_sign_cert_len;
    const uint8_t *ra_encrypt_cert_der; /* RA encryption cert DER */
    size_t         ra_encrypt_cert_len;
    int            single_cert;         /* 1 if one cert carries both KeyUsage bits */
} scep_cacert_bundle_t;

/* -----------------------------------------------------------------------
 * 1. Key generation
 *    RFC 8894 §2.2: "The requester MUST generate an ECC or RSA key pair."
 *    We generate RSA-2048 (required by NDES in legacy CryptoAPI/CSP mode).
 * --------------------------------------------------------------------- */

/**
 * scep_generate_keypair() -- generate an RSA-2048 key pair.
 *
 * @param out    Caller-allocated mbedtls_pk_context (not yet initialised).
 * @param f_rng  RNG function (e.g. mbedtls_ctr_drbg_random).
 * @param p_rng  RNG context (e.g. mbedtls_ctr_drbg_context*).
 * @return 0 on success, negative mbedTLS error code on failure.
 */
int scep_generate_keypair(mbedtls_pk_context *out,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);

/* -----------------------------------------------------------------------
 * 2. CSR generation
 *    RFC 8894 §2.2: PKCS#10 CertificationRequest with challengePassword
 *    (PKCS#9 attribute OID 1.2.840.113549.1.9.7) signed with the private key.
 * --------------------------------------------------------------------- */

/**
 * scep_build_csr() -- build a DER-encoded PKCS#10 CSR.
 *
 * @param subject            Subject name fields.
 * @param key                Signing key (RSA-2048, private+public).
 * @param challenge_password SCEP challenge password (NUL-terminated).
 * @param f_rng              RNG function.
 * @param p_rng              RNG context.
 * @param out_der            Output buffer for DER CSR.
 * @param out_len            In: capacity; Out: bytes written.
 * @return 0 on success, negative on failure.
 */
int scep_build_csr(const scep_subject_t *subject,
                   mbedtls_pk_context   *key,
                   const char           *challenge_password,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void                 *p_rng,
                   uint8_t              *out_der,
                   size_t               *out_len);

/* -----------------------------------------------------------------------
 * 3. Transaction ID derivation
 *    RFC 8894 §3.1: transactionID = hex(SHA-256(SubjectPublicKeyInfo DER))
 * --------------------------------------------------------------------- */

/**
 * scep_transaction_id() -- derive the SCEP transactionID from SPKI DER.
 *
 * @param spki_der  DER-encoded SubjectPublicKeyInfo.
 * @param spki_len  Length of spki_der.
 * @param out_hex   Output buffer; will hold a NUL-terminated 64-char hex string.
 * @param out_cap   Must be >= SCEP_TRANSACTION_ID_HEX_LEN + 1.
 * @return 0 on success, -1 if out_cap is too small.
 */
int scep_transaction_id(const uint8_t *spki_der, size_t spki_len,
                        char *out_hex, size_t out_cap);

/* -----------------------------------------------------------------------
 * 4. PKCSReq pkiMessage (enrollment request)
 *    RFC 8894 §4.2: SignedData( EnvelopedData( PKCS#10 CSR ) )
 * --------------------------------------------------------------------- */

/**
 * scep_build_pkimessage_pkcsreq() -- build a SCEP PKCSReq pkiMessage.
 *
 * @param csr_der               DER-encoded PKCS#10 CSR (from scep_build_csr).
 * @param csr_len               Length of csr_der.
 * @param ra_cert_der           RA encryption certificate DER.
 * @param ra_cert_len           Length of ra_cert_der.
 * @param signing_key           Device private key (RSA-2048).
 * @param self_signed_cert_der  Self-signed cert DER for the signer-info cert.
 * @param self_signed_cert_len  Length of self_signed_cert_der.
 * @param f_rng                 RNG function (for CEK and nonce).
 * @param p_rng                 RNG context.
 * @param transaction_id        NUL-terminated hex transaction ID (64 chars).
 * @param out_p7                Output buffer for the DER pkiMessage.
 * @param out_p7_len            In: capacity; Out: bytes written.
 * @return 0 on success, negative on failure.
 */
int scep_build_pkimessage_pkcsreq(const uint8_t      *csr_der,
                                  size_t              csr_len,
                                  const uint8_t      *ra_cert_der,
                                  size_t              ra_cert_len,
                                  mbedtls_pk_context *signing_key,
                                  const uint8_t      *self_signed_cert_der,
                                  size_t              self_signed_cert_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void               *p_rng,
                                  const char         *transaction_id,
                                  uint8_t            *out_p7,
                                  size_t             *out_p7_len);

/* -----------------------------------------------------------------------
 * 5. Build self-signed cert (transient "transaction" cert)
 * --------------------------------------------------------------------- */

/**
 * scep_build_self_signed_cert() -- build a minimal self-signed DER cert.
 *
 * @param subject    Subject/issuer fields (same value used for the CSR).
 * @param key        RSA-2048 key pair.
 * @param f_rng      RNG function.
 * @param p_rng      RNG context.
 * @param out_der    Output DER buffer.
 * @param out_len    In: capacity; Out: bytes written.
 * @return 0 on success, negative on failure.
 */
int scep_build_self_signed_cert(const scep_subject_t *subject,
                                mbedtls_pk_context   *key,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void                 *p_rng,
                                uint8_t              *out_der,
                                size_t               *out_len);

/* -----------------------------------------------------------------------
 * 6. CertRep response parsing
 *    RFC 8894 §4.3: SignedData( EnvelopedData( degenerate-SignedData( cert ) ) )
 * --------------------------------------------------------------------- */

/**
 * scep_parse_certrep() -- parse a SCEP CertRep (enrollment response).
 *
 * @param p7                      DER pkiMessage received from NDES.
 * @param p7_len                  Length.
 * @param expected_transaction_id Must match the transactionID in signed attrs.
 * @param recipient_key           Device private RSA-2048 key for decryption.
 * @param f_rng                   RNG function (for RSA blinding).
 * @param p_rng                   RNG context.
 * @param out_cert_der            Buffer to receive the issued cert DER.
 * @param out_cert_len            In: capacity; Out: bytes written (SUCCESS only).
 * @param out_status              pkiStatus from signed attributes.
 * @param out_fail_info           failInfo (SCEP_FAIL_INFO_NONE if not present).
 * @return 0 on success (check out_status for pkiStatus), negative on error.
 */
int scep_parse_certrep(const uint8_t      *p7,
                       size_t              p7_len,
                       const char         *expected_transaction_id,
                       mbedtls_pk_context *recipient_key,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void               *p_rng,
                       uint8_t            *out_cert_der,
                       size_t             *out_cert_len,
                       scep_pki_status_t  *out_status,
                       int                *out_fail_info);

/* -----------------------------------------------------------------------
 * 7. GetCACert response parsing
 *    RFC 8894 §4.1: degenerate PKCS#7 SignedData with no signers, only certs.
 * --------------------------------------------------------------------- */

/**
 * scep_parse_getcacert() -- parse a GetCACert PKCS#7 response.
 *
 * @param p7     Raw DER (or BER) PKCS#7 from server.
 * @param p7_len Length.
 * @param out    Filled with DER pointers into p7 memory (do not free
 *               individual fields -- they alias p7).
 * @return 0 on success, negative on structural error.
 */
int scep_parse_getcacert(const uint8_t       *p7,
                         size_t               p7_len,
                         scep_cacert_bundle_t *out);

/* -----------------------------------------------------------------------
 * Test-only mirror: parse a PKCSReq pkiMessage (reverse of build)
 * Only compiled when SCEP_PROTO_TEST_HELPERS is defined.
 * --------------------------------------------------------------------- */

#ifdef SCEP_PROTO_TEST_HELPERS

typedef struct {
    uint8_t  csr_der[SCEP_MAX_CSR_DER];
    size_t   csr_len;
    char     message_type[8];       /* e.g. "19" */
    char     transaction_id[SCEP_TRANSACTION_ID_HEX_LEN + 1];
    uint8_t  sender_nonce[SCEP_NONCE_LEN];
} scep_pkcsreq_unpacked_t;

/**
 * scep_parse_pkimessage_pkcsreq_for_test() -- reverse of scep_build_pkimessage_pkcsreq.
 */
int scep_parse_pkimessage_pkcsreq_for_test(const uint8_t             *p7,
                                           size_t                     p7_len,
                                           mbedtls_pk_context        *ra_priv_key,
                                           const uint8_t             *ra_cert_der,
                                           size_t                     ra_cert_len,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void                      *p_rng,
                                           scep_pkcsreq_unpacked_t   *out);

#endif /* SCEP_PROTO_TEST_HELPERS */

#ifdef __cplusplus
}
#endif
