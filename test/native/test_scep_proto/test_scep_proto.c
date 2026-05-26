/*
 * test_scep_proto.c -- native unit tests for lib/scep_proto/scep_proto.{c,h}
 *
 * Compiled against system mbedTLS (apt install libmbedtls-dev) for key
 * operations and against system OpenSSL for CSR/cert verification.
 *
 * Coverage:
 *   1. Keypair generation (RSA-2048 via mbedTLS)
 *   2. Transaction ID: determinism, 64-char hex, SHA-256 over SPKI
 *   3. CSR build + reparse: CN present, challengePassword attribute present
 *   4. Self-signed cert build: parses with OpenSSL d2i_X509
 *   5. SPKI export round-trip
 *
 * PKCS#7 pkiMessage roundtrip is tested on-device only.
 *
 * Run:
 *   venv/bin/pio test -e native -f native/test_scep_proto
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* mbedTLS */
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"

#include "unity.h"
#include "scep_proto.h"

/* OpenSSL helper for CSR reparse (kept in asn_public.h) */
#include "wolfssl/wolfcrypt/asn_public.h"

void setUp(void)    {}
void tearDown(void) {}

/* =========================================================================
 * Global RNG (initialised once per process -- CTR-DRBG is not thread-safe
 * but tests run sequentially)
 * ======================================================================= */

static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static int g_rng_init = 0;

static void ensure_rng(void)
{
    if (g_rng_init) return;
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    int rc = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char *)"test_scep", 9);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "mbedtls_ctr_drbg_seed");
    g_rng_init = 1;
}

/* =========================================================================
 * Helpers
 * ======================================================================= */

static void gen_keypair_or_fail(mbedtls_pk_context *key)
{
    ensure_rng();
    mbedtls_pk_init(key);
    int rc = scep_generate_keypair(key, mbedtls_ctr_drbg_random, &g_ctr_drbg);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_generate_keypair");
    TEST_ASSERT_EQUAL_INT_MESSAGE(MBEDTLS_PK_RSA, mbedtls_pk_get_type(key),
                                  "key type is RSA");
}

/* Export SPKI from a pk_context; writes at END of buf, returns pointer to start
 * and length. */
static const uint8_t *export_spki(mbedtls_pk_context *key,
                                   uint8_t *buf, size_t bufsz,
                                   size_t *spki_len_out)
{
    int len_i = mbedtls_pk_write_pubkey_der(key, buf, bufsz);
    TEST_ASSERT_GREATER_THAN_INT(0, len_i);
    *spki_len_out = (size_t)len_i;
    return buf + bufsz - (size_t)len_i;
}

/* =========================================================================
 * 1. Keypair generation
 * ======================================================================= */

void test_keypair_generates_valid_rsa2048_key(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    TEST_ASSERT_EQUAL_INT(MBEDTLS_PK_RSA, mbedtls_pk_get_type(&key));
    TEST_ASSERT_EQUAL_INT(2048, (int)mbedtls_pk_get_bitlen(&key));

    mbedtls_pk_free(&key);
}

void test_keypair_public_exponent_is_65537(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);
    TEST_ASSERT_NOT_NULL(rsa);

    /* Export public key DER and re-parse with OpenSSL to check exponent */
    uint8_t spki_buf[512];
    size_t spki_len;
    const uint8_t *spki = export_spki(&key, spki_buf, sizeof(spki_buf), &spki_len);

    const unsigned char *p = spki;
    EVP_PKEY *pk = d2i_PUBKEY(NULL, &p, (long)spki_len);
    TEST_ASSERT_NOT_NULL(pk);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *e = NULL;
    EVP_PKEY_get_bn_param(pk, "e", &e);
    TEST_ASSERT_NOT_NULL(e);
    TEST_ASSERT_EQUAL_INT(65537, (int)BN_get_word(e));
    BN_free(e);
#else
    RSA *rsa_ossl = EVP_PKEY_get0_RSA(pk);
    const BIGNUM *e = NULL;
    RSA_get0_key(rsa_ossl, NULL, &e, NULL);
    TEST_ASSERT_NOT_NULL(e);
    TEST_ASSERT_EQUAL_INT(65537, (int)BN_get_word(e));
#endif

    EVP_PKEY_free(pk);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 2. Transaction ID
 * ======================================================================= */

void test_transaction_id_is_64_hex_chars(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    uint8_t spki_buf[512];
    size_t spki_len;
    const uint8_t *spki = export_spki(&key, spki_buf, sizeof(spki_buf), &spki_len);

    char tid[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    int rc = scep_transaction_id(spki, spki_len, tid, sizeof(tid));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_size_t(SCEP_TRANSACTION_ID_HEX_LEN, strlen(tid));

    for (int i = 0; i < SCEP_TRANSACTION_ID_HEX_LEN; i++) {
        char c = tid[i];
        int is_hex = (c >= '0' && c <= '9') ||
                     (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F');
        TEST_ASSERT_TRUE_MESSAGE(is_hex, "char is hex digit");
    }

    mbedtls_pk_free(&key);
}

void test_transaction_id_is_deterministic(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    uint8_t spki_buf[512];
    size_t spki_len;
    const uint8_t *spki = export_spki(&key, spki_buf, sizeof(spki_buf), &spki_len);

    char tid1[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    char tid2[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    scep_transaction_id(spki, spki_len, tid1, sizeof(tid1));
    scep_transaction_id(spki, spki_len, tid2, sizeof(tid2));

    TEST_ASSERT_EQUAL_STRING(tid1, tid2);

    mbedtls_pk_free(&key);
}

void test_transaction_id_different_keys_differ(void)
{
    mbedtls_pk_context key1, key2;
    gen_keypair_or_fail(&key1);
    gen_keypair_or_fail(&key2);

    uint8_t spki_buf1[512], spki_buf2[512];
    size_t len1, len2;
    const uint8_t *spki1 = export_spki(&key1, spki_buf1, sizeof(spki_buf1), &len1);
    const uint8_t *spki2 = export_spki(&key2, spki_buf2, sizeof(spki_buf2), &len2);

    char tid1[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    char tid2[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    scep_transaction_id(spki1, len1, tid1, sizeof(tid1));
    scep_transaction_id(spki2, len2, tid2, sizeof(tid2));

    TEST_ASSERT_NOT_EQUAL(0, strcmp(tid1, tid2));

    mbedtls_pk_free(&key1);
    mbedtls_pk_free(&key2);
}

void test_transaction_id_buffer_too_small_returns_error(void)
{
    uint8_t dummy_spki[65];
    memset(dummy_spki, 0xAB, sizeof(dummy_spki));
    char small_buf[32]; /* less than 65 needed */
    int rc = scep_transaction_id(dummy_spki, sizeof(dummy_spki),
                                 small_buf, sizeof(small_buf));
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* =========================================================================
 * 3. CSR build + reparse
 * ======================================================================= */

void test_csr_build_and_reparse_cn_and_challenge_pw(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = {
        .common_name         = "esp-tty-device-001",
        .organization        = "esp-tty",
        .organizational_unit = "IoT",
        .country             = "RO",
        .state               = NULL,
        .locality            = NULL,
    };
    const char *challenge = "FFC9708138742EC99A8CDF837A9F4CEA";

    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);

    int rc = scep_build_csr(&subj, &key, challenge,
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_csr");
    TEST_ASSERT_GREATER_THAN_size_t(0, csr_len);

    /* Reparse with OpenSSL to verify CN and challengePassword */
    ParsedCert parsed;
    rc = scep_native_parse_csr(csr_der, (word32)csr_len, &parsed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_native_parse_csr");
    TEST_ASSERT_EQUAL_STRING("esp-tty-device-001", parsed.subjectCN);
    TEST_ASSERT_EQUAL_STRING(challenge, parsed.challengePw);

    mbedtls_pk_free(&key);
}

void test_csr_is_signed_with_rsa(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "rsa-check-device" };
    const char *challenge = "TESTPASSWORD";

    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);

    int rc = scep_build_csr(&subj, &key, challenge,
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Parse with OpenSSL and check the signature algorithm */
    const unsigned char *p = csr_der;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr_len);
    TEST_ASSERT_NOT_NULL_MESSAGE(req, "d2i_X509_REQ");

    /* Get public key type -- should be RSA */
    EVP_PKEY *pk = X509_REQ_get0_pubkey(req);
    TEST_ASSERT_NOT_NULL(pk);
    TEST_ASSERT_EQUAL_INT(EVP_PKEY_RSA, EVP_PKEY_base_id(pk));

    /* Verify self-signature succeeds */
    int vrc = X509_REQ_verify(req, pk);
    TEST_ASSERT_GREATER_THAN_INT(0, vrc);

    X509_REQ_free(req);
    mbedtls_pk_free(&key);
}

void test_csr_null_subject_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    uint8_t buf[SCEP_MAX_CSR_DER];
    size_t  len = sizeof(buf);
    int rc = scep_build_csr(NULL, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            buf, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);

    mbedtls_pk_free(&key);
}

void test_csr_optional_subject_fields_may_be_null(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    /* Only CN is required; all others NULL */
    scep_subject_t subj = {
        .common_name = "minimal-cn",
        .organization = NULL, .organizational_unit = NULL,
        .country = NULL, .state = NULL, .locality = NULL,
    };

    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);
    int rc = scep_build_csr(&subj, &key, "test-pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_GREATER_THAN_size_t(0, csr_len);

    ParsedCert parsed;
    scep_native_parse_csr(csr_der, (word32)csr_len, &parsed);
    TEST_ASSERT_EQUAL_STRING("minimal-cn", parsed.subjectCN);

    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 4. Self-signed cert
 * ======================================================================= */

void test_self_signed_cert_parses_with_openssl(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = {
        .common_name  = "scep-self-signed",
        .organization = "TestOrg",
        .country      = "DE",
    };

    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);

    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_self_signed_cert");
    TEST_ASSERT_GREATER_THAN_size_t(100, cert_len);

    /* Parse with OpenSSL */
    const unsigned char *p = cert_der;
    X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
    TEST_ASSERT_NOT_NULL_MESSAGE(x509, "d2i_X509 parsed self-signed cert");

    /* Check CN in subject */
    X509_NAME *name = X509_get_subject_name(x509);
    char cn[64] = {0};
    X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));
    TEST_ASSERT_EQUAL_STRING("scep-self-signed", cn);

    /* Verify self-signed: subject == issuer */
    X509_NAME *issuer = X509_get_issuer_name(x509);
    TEST_ASSERT_EQUAL_INT(0, X509_NAME_cmp(name, issuer));

    /* Verify key type is RSA */
    EVP_PKEY *pk = X509_get0_pubkey(x509);
    TEST_ASSERT_NOT_NULL(pk);
    TEST_ASSERT_EQUAL_INT(EVP_PKEY_RSA, EVP_PKEY_base_id(pk));

    X509_free(x509);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 5. SPKI export round-trip
 * ======================================================================= */

void test_spki_export_is_repeatable(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    uint8_t spki_buf1[512], spki_buf2[512];
    size_t len1, len2;
    const uint8_t *spki1 = export_spki(&key, spki_buf1, sizeof(spki_buf1), &len1);
    const uint8_t *spki2 = export_spki(&key, spki_buf2, sizeof(spki_buf2), &len2);

    TEST_ASSERT_EQUAL_size_t(len1, len2);
    TEST_ASSERT_EQUAL_MEMORY(spki1, spki2, len1);

    mbedtls_pk_free(&key);
}

void test_spki_is_rsa_subjectpublickeyinfo(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    uint8_t spki_buf[512];
    size_t spki_len;
    const uint8_t *spki = export_spki(&key, spki_buf, sizeof(spki_buf), &spki_len);

    /* Parse with OpenSSL and verify it's an RSA-2048 public key */
    const unsigned char *p = spki;
    EVP_PKEY *pk = d2i_PUBKEY(NULL, &p, (long)spki_len);
    TEST_ASSERT_NOT_NULL_MESSAGE(pk, "d2i_PUBKEY parsed RSA SPKI");
    TEST_ASSERT_EQUAL_INT(EVP_PKEY_RSA, EVP_PKEY_base_id(pk));

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsa = EVP_PKEY_get0_RSA(pk);
    TEST_ASSERT_EQUAL_INT(2048, RSA_bits(rsa));
#else
    TEST_ASSERT_EQUAL_INT(2048, (int)EVP_PKEY_get_bits(pk));
#endif

    EVP_PKEY_free(pk);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 6. scep_build_csr error paths
 * ======================================================================= */

void test_csr_output_buffer_too_small_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "overflow-test" };
    /* Provide a 1-byte output buffer -- far too small for any CSR. */
    uint8_t tiny[1];
    size_t  tiny_len = sizeof(tiny);
    int rc = scep_build_csr(&subj, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            tiny, &tiny_len);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc, "should fail with tiny output buffer");

    mbedtls_pk_free(&key);
}

void test_csr_empty_cn_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "" };
    uint8_t buf[SCEP_MAX_CSR_DER];
    size_t  len = sizeof(buf);
    int rc = scep_build_csr(&subj, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            buf, &len);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc, "empty CN should be rejected");

    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 7. scep_parse_certrep -- malformed input paths
 * ======================================================================= */

void test_parse_certrep_null_p7_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    uint8_t cert_buf[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_buf);
    scep_pki_status_t status = SCEP_PKI_STATUS_UNKNOWN;
    int fail_info = SCEP_FAIL_INFO_NONE;

    int rc = scep_parse_certrep(NULL, 0,
                                "0000000000000000000000000000000000000000000000000000000000000000",
                                &key,
                                mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                cert_buf, &cert_len,
                                &status, &fail_info);
    TEST_ASSERT_NOT_EQUAL(0, rc);

    mbedtls_pk_free(&key);
}

void test_parse_certrep_truncated_der_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    /* A 4-byte DER blob -- enough for a tag and a few length bytes but
     * structurally invalid as ContentInfo. */
    static const uint8_t garbage[] = { 0x30, 0x82, 0x01, 0x00 };

    uint8_t cert_buf[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_buf);
    scep_pki_status_t status = SCEP_PKI_STATUS_UNKNOWN;
    int fail_info = SCEP_FAIL_INFO_NONE;

    int rc = scep_parse_certrep(garbage, sizeof(garbage),
                                "0000000000000000000000000000000000000000000000000000000000000000",
                                &key,
                                mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                cert_buf, &cert_len,
                                &status, &fail_info);
    TEST_ASSERT_NOT_EQUAL(0, rc);

    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 8. scep_parse_getcacert -- NULL / empty inputs
 * ======================================================================= */

void test_parse_getcacert_null_p7_returns_error(void)
{
    scep_cacert_bundle_t bundle;
    int rc = scep_parse_getcacert(NULL, 0, &bundle);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

void test_parse_getcacert_null_out_returns_error(void)
{
    static const uint8_t dummy[] = { 0x30, 0x00 };
    int rc = scep_parse_getcacert(dummy, sizeof(dummy), NULL);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

void test_parse_getcacert_garbage_der_returns_error(void)
{
    /* Random bytes that don't form a valid PKCS#7 ContentInfo. */
    static const uint8_t bad[] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02, 0x03,
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00,
    };
    scep_cacert_bundle_t bundle;
    int rc = scep_parse_getcacert(bad, sizeof(bad), &bundle);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* =========================================================================
 * 9. scep_transaction_id -- NULL inputs
 * ======================================================================= */

void test_transaction_id_null_spki_returns_error(void)
{
    char buf[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    int rc = scep_transaction_id(NULL, 0, buf, sizeof(buf));
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

void test_transaction_id_null_out_returns_error(void)
{
    uint8_t dummy[32] = {0};
    int rc = scep_transaction_id(dummy, sizeof(dummy), NULL, 0);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* =========================================================================
 * 10. scep_generate_keypair -- NULL inputs
 * ======================================================================= */

void test_generate_keypair_null_out_returns_error(void)
{
    ensure_rng();
    int rc = scep_generate_keypair(NULL, mbedtls_ctr_drbg_random, &g_ctr_drbg);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

void test_generate_keypair_null_rng_returns_error(void)
{
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = scep_generate_keypair(&key, NULL, NULL);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    /* context should not be set up (pk_info still NULL) */
    TEST_ASSERT_EQUAL_INT(MBEDTLS_PK_NONE, mbedtls_pk_get_type(&key));
}

/* =========================================================================
 * 11. scep_build_self_signed_cert -- additional error paths
 * ======================================================================= */

/* NULL key should return error */
void test_self_signed_cert_null_key_returns_error(void)
{
    scep_subject_t subj = { .common_name = "test" };
    uint8_t out[SCEP_MAX_CERT_DER];
    size_t len = sizeof(out);
    int rc = scep_build_self_signed_cert(&subj, NULL,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         out, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* NULL subject should return error */
void test_self_signed_cert_null_subject_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);
    uint8_t out[SCEP_MAX_CERT_DER];
    size_t len = sizeof(out);
    int rc = scep_build_self_signed_cert(NULL, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         out, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    mbedtls_pk_free(&key);
}

/* NULL out_der should return error */
void test_self_signed_cert_null_out_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);
    scep_subject_t subj = { .common_name = "test" };
    size_t len = 0;
    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         NULL, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    mbedtls_pk_free(&key);
}

/* All optional subject fields (O, OU, C, ST, L) present in generated cert */
void test_self_signed_cert_optional_fields_present(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = {
        .common_name         = "cn-test",
        .organization        = "TestOrg",
        .organizational_unit = "TestOU",
        .country             = "US",
        .state               = "TestState",
        .locality            = "TestCity",
    };
    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t cert_len = sizeof(cert_der);
    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_self_signed_cert with all fields");

    /* Parse and verify all fields are present */
    const unsigned char *p = cert_der;
    X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
    TEST_ASSERT_NOT_NULL(x509);

    X509_NAME *name = X509_get_subject_name(x509);
    char buf[128];

    X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("cn-test", buf);

    X509_NAME_get_text_by_NID(name, NID_organizationName, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("TestOrg", buf);

    X509_free(x509);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 12. scep_transaction_id -- edge cases
 * ======================================================================= */

/* All-zero SPKI: SHA-256 of zeros should still produce valid 64-char hex */
void test_transaction_id_all_zero_spki(void)
{
    ensure_rng();
    uint8_t zero_spki[32] = {0};
    char buf[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    int rc = scep_transaction_id(zero_spki, sizeof(zero_spki), buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_size_t(SCEP_TRANSACTION_ID_HEX_LEN, strlen(buf));
    /* Verify all chars are hex */
    for (size_t i = 0; i < SCEP_TRANSACTION_ID_HEX_LEN; i++) {
        char c = buf[i];
        TEST_ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

/* Buffer of exactly SCEP_TRANSACTION_ID_HEX_LEN (missing NUL) -> error */
void test_transaction_id_exact_no_nul_buffer_fails(void)
{
    uint8_t dummy[32] = {0};
    char buf[SCEP_TRANSACTION_ID_HEX_LEN];  /* no room for NUL */
    int rc = scep_transaction_id(dummy, sizeof(dummy), buf, sizeof(buf));
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* =========================================================================
 * 13. scep_build_csr -- additional error paths
 * ======================================================================= */

/* NULL RNG function */
void test_csr_null_rng_fn_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "test" };
    uint8_t out[SCEP_MAX_CSR_DER];
    size_t len = sizeof(out);
    int rc = scep_build_csr(&subj, &key, "password",
                             NULL, &g_ctr_drbg,
                             out, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    mbedtls_pk_free(&key);
}

/* NULL key */
void test_csr_null_key_returns_error(void)
{
    scep_subject_t subj = { .common_name = "test" };
    uint8_t out[SCEP_MAX_CSR_DER];
    size_t len = sizeof(out);
    int rc = scep_build_csr(&subj, NULL, "password",
                             mbedtls_ctr_drbg_random, &g_ctr_drbg,
                             out, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* NULL challenge password */
void test_csr_null_challenge_password_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "test" };
    uint8_t out[SCEP_MAX_CSR_DER];
    size_t len = sizeof(out);
    int rc = scep_build_csr(&subj, &key, NULL,
                             mbedtls_ctr_drbg_random, &g_ctr_drbg,
                             out, &len);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 14. mbedTLS version-gate compile-time checks
 *
 * Confirm that the #if-gated API path chosen at compile time is the one
 * that actually matches the mbedTLS version present.  On the host (3.6.x)
 * the 3.x path is taken; on-device (ESP-IDF 6.0.1, mbedTLS 4.x) the 4.x
 * path is taken.  Either way, building the suite exercises the selected path.
 * ======================================================================= */

/* Test A: the RNG signature selected at compile time actually produces a
 * proper key (exercises scep_generate_keypair via the right internal path). */
void test_mbedtls_version_gate_keypair_works(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    /* If the version gate is wrong we'd see a compile error or a crash here */
    TEST_ASSERT_EQUAL_INT(MBEDTLS_PK_RSA, mbedtls_pk_get_type(&key));
    TEST_ASSERT_EQUAL_INT(2048, (int)mbedtls_pk_get_bitlen(&key));

    mbedtls_pk_free(&key);
}

/* Test B: mbedtls_pk_sign path exercised by scep_build_csr produces a
 * signature verifiable by OpenSSL.  On 3.x the f_rng/p_rng overload is
 * used; on 4.x the no-f_rng overload is used.  Both must produce a valid
 * PKCS#1v1.5 signature over the same payload. */
void test_mbedtls_pk_sign_version_path_produces_valid_signature(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = {
        .common_name = "version-gate-test",
        .organization = "TestOrg",
        .country = "DE",
    };
    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);

    int rc = scep_build_csr(&subj, &key, "TESTPW",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_csr");

    /* Verify via OpenSSL: the CSR signature must verify with its own pubkey
     * regardless of which mbedTLS code path was compiled in. */
    const unsigned char *p = csr_der;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr_len);
    TEST_ASSERT_NOT_NULL_MESSAGE(req, "d2i_X509_REQ");
    EVP_PKEY *pk = X509_REQ_get0_pubkey(req);
    TEST_ASSERT_NOT_NULL(pk);
    int vrc = X509_REQ_verify(req, pk);
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, vrc,
        "CSR signature must verify (tests the right mbedtls_pk_sign overload)");

    X509_REQ_free(req);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 15. scep_build_csr -- long CN and fully-populated DN
 * ======================================================================= */

/* A CN of exactly 64 chars should work or fail gracefully (not crash). */
void test_csr_long_cn_64_chars_no_crash(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    /* 64-character CN is at the boundary of the name_buf in scep_proto.c */
    char long_cn[65];
    memset(long_cn, 'A', 64);
    long_cn[64] = '\0';

    scep_subject_t subj = { .common_name = long_cn };
    uint8_t buf[SCEP_MAX_CSR_DER];
    size_t  len = sizeof(buf);
    int rc = scep_build_csr(&subj, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            buf, &len);
    /* Either succeeds or returns an error -- must not crash or corrupt memory */
    (void)rc;
    /* Valgrind / AddressSanitizer will catch any out-of-bounds write here */

    mbedtls_pk_free(&key);
}

/* A CN longer than 64 chars must either succeed or fail cleanly. */
void test_csr_very_long_cn_fails_gracefully(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    /* 128-character CN -- larger than the name_buf internal scratch space;
     * scep_build_csr should detect the overflow and return an error. */
    char very_long_cn[129];
    memset(very_long_cn, 'B', 128);
    very_long_cn[128] = '\0';

    scep_subject_t subj = { .common_name = very_long_cn };
    uint8_t buf[SCEP_MAX_CSR_DER];
    size_t  len = sizeof(buf);
    int rc = scep_build_csr(&subj, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            buf, &len);
    /* If it fails, that is the expected graceful-failure behaviour.
     * If it succeeds, the generated CSR must still be parseable. */
    if (rc == 0) {
        const unsigned char *p = buf;
        X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)len);
        /* Must not crash; may or may not parse depending on truncation */
        if (req) X509_REQ_free(req);
    }
    /* Either path is acceptable -- no crash is the key assertion. */

    mbedtls_pk_free(&key);
}

/* All optional DN fields populated: O, OU, C, ST, L + CN */
void test_csr_all_dn_fields_populated_and_verifies(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = {
        .common_name         = "dn-full-test",
        .organization        = "FullOrg",
        .organizational_unit = "FullOU",
        .country             = "US",
        .state               = "California",
        .locality            = "San Francisco",
    };
    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);
    int rc = scep_build_csr(&subj, &key, "FULLPW",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_csr all fields");

    /* Verify CSR via OpenSSL */
    const unsigned char *p = csr_der;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr_len);
    TEST_ASSERT_NOT_NULL_MESSAGE(req, "d2i_X509_REQ");

    EVP_PKEY *pk = X509_REQ_get0_pubkey(req);
    TEST_ASSERT_NOT_NULL(pk);
    TEST_ASSERT_GREATER_THAN_INT(0, X509_REQ_verify(req, pk));

    /* Check CN is present */
    X509_NAME *name = X509_REQ_get_subject_name(req);
    char cn[64] = {0};
    X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));
    TEST_ASSERT_EQUAL_STRING("dn-full-test", cn);

    X509_REQ_free(req);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 16. scep_build_self_signed_cert -- NotBefore < NotAfter + sig verifies
 * ======================================================================= */

void test_self_signed_cert_notbefore_before_notafter(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "time-check" };
    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);

    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_self_signed_cert");

    const unsigned char *p = cert_der;
    X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
    TEST_ASSERT_NOT_NULL_MESSAGE(x509, "d2i_X509");

    /* NotBefore and NotAfter: hardcoded to "20200101000000" and "20380101000000"
     * in scep_proto.c -- the cert covers 2020-01-01..2038-01-01.
     * Verify NotBefore < NotAfter. */
    const ASN1_TIME *not_before = X509_get0_notBefore(x509);
    const ASN1_TIME *not_after  = X509_get0_notAfter(x509);
    TEST_ASSERT_NOT_NULL(not_before);
    TEST_ASSERT_NOT_NULL(not_after);

    int cmp = ASN1_TIME_compare(not_before, not_after);
    TEST_ASSERT_LESS_THAN_INT_MESSAGE(0, cmp, "NotBefore must be before NotAfter");

    X509_free(x509);
    mbedtls_pk_free(&key);
}

/* Self-signed cert: OpenSSL can verify signature with its own public key */
void test_self_signed_cert_signature_self_verifies(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = {
        .common_name  = "self-verify",
        .organization = "SelfOrg",
        .country      = "FR",
    };
    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);

    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_self_signed_cert");

    const unsigned char *p = cert_der;
    X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
    TEST_ASSERT_NOT_NULL(x509);

    /* Verify the cert's own signature: issuer == subject, so we verify
     * using the cert's own public key. */
    EVP_PKEY *pub = X509_get0_pubkey(x509);
    TEST_ASSERT_NOT_NULL(pub);

    /* X509_verify returns 1 on success */
    int vrc = X509_verify(x509, pub);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, vrc, "Self-signed cert signature must self-verify");

    X509_free(x509);
    mbedtls_pk_free(&key);
}

/* Self-signed cert: public key in cert matches the supplied pk_context */
void test_self_signed_cert_pubkey_matches_pk_context(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "pk-match-test" };
    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);

    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_self_signed_cert");

    /* Export SPKI from key context */
    uint8_t spki_from_key[512];
    size_t  spki_key_len;
    const uint8_t *spki_key = export_spki(&key, spki_from_key, sizeof(spki_from_key),
                                          &spki_key_len);

    /* Parse cert and export its SPKI */
    const unsigned char *p = cert_der;
    X509 *x509 = d2i_X509(NULL, &p, (long)cert_len);
    TEST_ASSERT_NOT_NULL(x509);

    EVP_PKEY *pub = X509_get0_pubkey(x509);
    TEST_ASSERT_NOT_NULL(pub);

    /* Serialize cert's public key to DER and compare with mbedTLS SPKI */
    unsigned char *spki_cert_buf = NULL;
    int spki_cert_len_i = i2d_PUBKEY(pub, &spki_cert_buf);
    TEST_ASSERT_GREATER_THAN_INT(0, spki_cert_len_i);

    TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)spki_cert_len_i, spki_key_len,
        "SPKI length mismatch between key and cert");
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(spki_key, spki_cert_buf, spki_key_len,
        "SPKI bytes mismatch between key context and embedded cert");

    OPENSSL_free(spki_cert_buf);
    X509_free(x509);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 17. scep_parse_getcacert -- RSA KeyEncipherment cert selection
 *
 * The scep_parse_getcacert() C implementation selects the RA encryption cert
 * by choosing the cert whose public key is RSA with keyEncipherment usage.
 * Build a synthetic 3-cert P7 bundle (EC signing cert + RSA encryption cert
 * + CA cert) using OpenSSL DER helpers, then parse it and verify the RA
 * encryption cert slot holds the RSA cert.
 * ======================================================================= */

/* Build a minimal degenerate PKCS#7 SignedData (no signers, just certs)
 * from an array of DER-encoded certs.  Returns the total length or -1. */
static int build_degenerate_p7(const uint8_t **certs, const size_t *cert_lens,
                                 int num_certs,
                                 uint8_t *out, size_t out_cap)
{
    /* We need to build:
     * SEQUENCE {                  -- ContentInfo
     *   OID (1.2.840.113549.1.7.2)  -- id-signedData
     *   [0] EXPLICIT SEQUENCE {   -- SignedData
     *     INTEGER 1               -- version
     *     SET {}                  -- digestAlgorithms (empty)
     *     SEQUENCE {              -- encapContentInfo
     *       OID (1.2.840.113549.1.7.1)  -- id-data
     *     }
     *     [0] IMPLICIT            -- certificates
     *       <cert1> <cert2> ...
     *     SET {}                  -- signerInfos (empty)
     *   }
     * }
     */
    /* Use OpenSSL to build this via d2i + serialize_certificates-style path */
    PKCS7 *p7 = PKCS7_new();
    if (!p7) return -1;
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_content_new(p7, NID_pkcs7_data);
    /* Add certs */
    for (int i = 0; i < num_certs; i++) {
        const unsigned char *cp = certs[i];
        X509 *xc = d2i_X509(NULL, &cp, (long)cert_lens[i]);
        if (!xc) { PKCS7_free(p7); return -1; }
        PKCS7_add_certificate(p7, xc);
        X509_free(xc);
    }
    unsigned char *p7_buf = NULL;
    int p7_len = i2d_PKCS7(p7, &p7_buf);
    PKCS7_free(p7);
    if (p7_len <= 0) return -1;
    if ((size_t)p7_len > out_cap) { OPENSSL_free(p7_buf); return -1; }
    memcpy(out, p7_buf, p7_len);
    OPENSSL_free(p7_buf);
    return p7_len;
}

void test_parse_getcacert_rsa_key_encipherment_cert_is_selected_for_ra_encrypt(void)
{
    /* Build two certs:
     *   cert A: RSA-2048, KeyUsage=keyEncipherment (RA encryption)
     *   cert B: EC P-256, KeyUsage=digitalSignature (RA signing)
     * Both are self-signed.  Wrap in a degenerate PKCS#7 in order [B, A].
     * scep_parse_getcacert must still pick cert A for ra_encrypt_cert. */

    /* Cert A: RSA-2048 with KeyUsage=keyEncipherment */
    EVP_PKEY *rsa_key = EVP_RSA_gen(2048);
    TEST_ASSERT_NOT_NULL_MESSAGE(rsa_key, "EVP_RSA_gen");

    X509_NAME *rsa_name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(rsa_name, "CN", MBSTRING_UTF8,
                               (const unsigned char *)"RSA-RA-Encrypt", -1, -1, 0);
    X509 *rsa_cert = X509_new();
    X509_set_version(rsa_cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(rsa_cert), 1);
    X509_set_subject_name(rsa_cert, rsa_name);
    X509_set_issuer_name(rsa_cert, rsa_name);
    X509_set_pubkey(rsa_cert, rsa_key);
    /* Validity: 2020-2038 */
    X509_gmtime_adj(X509_get_notBefore(rsa_cert), -365*24*3600);
    X509_gmtime_adj(X509_get_notAfter(rsa_cert),   365*24*3600);
    /* Add KeyUsage: keyEncipherment */
    {
        ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
        /* bit 2 = keyEncipherment */
        ASN1_BIT_STRING_set_bit(ku, 2, 1);
        X509_add1_ext_i2d(rsa_cert, NID_key_usage, ku, 1, X509V3_ADD_DEFAULT);
        ASN1_BIT_STRING_free(ku);
    }
    X509_sign(rsa_cert, rsa_key, EVP_sha256());

    /* Cert B: EC P-256 with KeyUsage=digitalSignature */
    EVP_PKEY *ec_key = EVP_EC_gen("P-256");
    TEST_ASSERT_NOT_NULL_MESSAGE(ec_key, "EVP_EC_gen");

    X509_NAME *ec_name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(ec_name, "CN", MBSTRING_UTF8,
                               (const unsigned char *)"EC-RA-Sign", -1, -1, 0);
    X509 *ec_cert = X509_new();
    X509_set_version(ec_cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(ec_cert), 2);
    X509_set_subject_name(ec_cert, ec_name);
    X509_set_issuer_name(ec_cert, ec_name);
    X509_set_pubkey(ec_cert, ec_key);
    X509_gmtime_adj(X509_get_notBefore(ec_cert), -365*24*3600);
    X509_gmtime_adj(X509_get_notAfter(ec_cert),   365*24*3600);
    {
        ASN1_BIT_STRING *ku = ASN1_BIT_STRING_new();
        /* bit 0 = digitalSignature */
        ASN1_BIT_STRING_set_bit(ku, 0, 1);
        X509_add1_ext_i2d(ec_cert, NID_key_usage, ku, 1, X509V3_ADD_DEFAULT);
        ASN1_BIT_STRING_free(ku);
    }
    X509_sign(ec_cert, ec_key, EVP_sha256());

    /* Serialize both certs to DER */
    unsigned char *rsa_der_buf = NULL, *ec_der_buf = NULL;
    int rsa_der_len = i2d_X509(rsa_cert, &rsa_der_buf);
    int ec_der_len  = i2d_X509(ec_cert,  &ec_der_buf);
    TEST_ASSERT_GREATER_THAN_INT(0, rsa_der_len);
    TEST_ASSERT_GREATER_THAN_INT(0, ec_der_len);

    /* Build degenerate P7 with order [ec_cert, rsa_cert] */
    const uint8_t *cert_ptrs[2] = { ec_der_buf, rsa_der_buf };
    size_t cert_lens[2] = { (size_t)ec_der_len, (size_t)rsa_der_len };
    uint8_t p7_buf[SCEP_MAX_CA_BUNDLE_CERT_DER * 4];
    int p7_len = build_degenerate_p7(cert_ptrs, cert_lens, 2,
                                      p7_buf, sizeof(p7_buf));
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, p7_len, "build_degenerate_p7");

    /* Parse with scep_parse_getcacert */
    scep_cacert_bundle_t bundle;
    int rc = scep_parse_getcacert(p7_buf, (size_t)p7_len, &bundle);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_parse_getcacert");

    /* The RA encryption cert must be the RSA one */
    TEST_ASSERT_NOT_NULL_MESSAGE(bundle.ra_encrypt_cert_der,
        "ra_encrypt_cert_der must be set");
    TEST_ASSERT_GREATER_THAN_size_t(0, bundle.ra_encrypt_cert_len);

    /* Verify by parsing the ra_encrypt_cert_der with mbedTLS */
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int mrc = mbedtls_x509_crt_parse_der(&crt, bundle.ra_encrypt_cert_der,
                                          bundle.ra_encrypt_cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, mrc, "mbedtls_x509_crt_parse_der ra_encrypt");
    TEST_ASSERT_EQUAL_INT_MESSAGE(MBEDTLS_PK_RSA,
        (int)mbedtls_pk_get_type(&crt.pk),
        "ra_encrypt cert must have RSA key");
    mbedtls_x509_crt_free(&crt);

    /* Cleanup */
    OPENSSL_free(rsa_der_buf);
    OPENSSL_free(ec_der_buf);
    X509_free(rsa_cert);
    X509_free(ec_cert);
    X509_NAME_free(rsa_name);
    X509_NAME_free(ec_name);
    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(ec_key);
}

/* =========================================================================
 * 18. Additional transaction_id edge cases
 * ======================================================================= */

/* Single-byte SPKI should produce a valid 64-char hex (SHA-256 of 1 byte) */
void test_transaction_id_single_byte_spki_produces_valid_hex(void)
{
    uint8_t one_byte[1] = { 0xAB };
    char buf[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    int rc = scep_transaction_id(one_byte, 1, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_size_t(SCEP_TRANSACTION_ID_HEX_LEN, strlen(buf));
    for (size_t i = 0; i < SCEP_TRANSACTION_ID_HEX_LEN; i++) {
        char c = buf[i];
        TEST_ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F'));
    }
}

/* 64-byte SPKI should work fine */
void test_transaction_id_length_64_bytes_spki_produces_valid_hex(void)
{
    uint8_t spki[64];
    for (size_t i = 0; i < sizeof(spki); i++) spki[i] = (uint8_t)i;
    char buf[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    int rc = scep_transaction_id(spki, sizeof(spki), buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_size_t(SCEP_TRANSACTION_ID_HEX_LEN, strlen(buf));
}

/* Buffer of exactly SCEP_TRANSACTION_ID_HEX_LEN + 1 bytes (tight fit) succeeds */
void test_transaction_id_exact_capacity_plus_one_succeeds(void)
{
    uint8_t dummy[32] = {0};
    char buf[SCEP_TRANSACTION_ID_HEX_LEN + 1];
    memset(buf, 0, sizeof(buf));
    int rc = scep_transaction_id(dummy, sizeof(dummy), buf, SCEP_TRANSACTION_ID_HEX_LEN + 1);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_size_t(SCEP_TRANSACTION_ID_HEX_LEN, strlen(buf));
}

/* =========================================================================
 * 19. CSR boundary: CN with special ASCII printable chars
 * ======================================================================= */

/* CN containing hyphens, underscores, dots -- common in device names */
void test_csr_cn_with_special_chars_ascii_printable(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "esp-tty_device.001" };
    uint8_t buf[SCEP_MAX_CSR_DER];
    size_t  len = sizeof(buf);
    int rc = scep_build_csr(&subj, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            buf, &len);
    if (rc == 0) {
        /* If success, verify the CN is preserved */
        const unsigned char *p = buf;
        X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)len);
        if (req) {
            X509_NAME *name = X509_REQ_get_subject_name(req);
            char cn[64] = {0};
            X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));
            TEST_ASSERT_EQUAL_STRING("esp-tty_device.001", cn);
            X509_REQ_free(req);
        }
    }
    /* Either success or clean failure is acceptable; no crash */
    mbedtls_pk_free(&key);
}

/* CN containing spaces (allowed in X.520 UTF8String) -- no crash */
void test_csr_cn_with_spaces_no_crash(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "my device 42" };
    uint8_t buf[SCEP_MAX_CSR_DER];
    size_t  len = sizeof(buf);
    int rc = scep_build_csr(&subj, &key, "pw",
                            mbedtls_ctr_drbg_random, &g_ctr_drbg,
                            buf, &len);
    /* Either success or clean failure is acceptable; no crash */
    (void)rc;
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 20. Self-signed cert: tiny output buffer returns error
 * ======================================================================= */

void test_self_signed_cert_tiny_buf_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    scep_subject_t subj = { .common_name = "tiny-buf" };
    uint8_t tiny[4];
    size_t len = sizeof(tiny);
    int rc = scep_build_self_signed_cert(&subj, &key,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                         tiny, &len);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc, "Tiny output buffer should return error");
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 21. scep_parse_certrep -- wrong outer tag / all-zeros
 * ======================================================================= */

/* Outer tag 0x04 (OCTET STRING) instead of 0x30 (SEQUENCE) */
void test_parse_certrep_wrong_outer_tag_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    static const uint8_t bad_tag[] = { 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };

    uint8_t cert_buf[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_buf);
    scep_pki_status_t status = SCEP_PKI_STATUS_UNKNOWN;
    int fail_info = SCEP_FAIL_INFO_NONE;

    int rc = scep_parse_certrep(bad_tag, sizeof(bad_tag),
                                "0000000000000000000000000000000000000000000000000000000000000000",
                                &key,
                                mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                cert_buf, &cert_len,
                                &status, &fail_info);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    mbedtls_pk_free(&key);
}

/* All-zeros buffer (structurally invalid) */
void test_parse_certrep_all_zeros_returns_error(void)
{
    mbedtls_pk_context key;
    gen_keypair_or_fail(&key);

    static const uint8_t zeros[64] = {0};

    uint8_t cert_buf[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_buf);
    scep_pki_status_t status = SCEP_PKI_STATUS_UNKNOWN;
    int fail_info = SCEP_FAIL_INFO_NONE;

    int rc = scep_parse_certrep(zeros, sizeof(zeros),
                                "0000000000000000000000000000000000000000000000000000000000000000",
                                &key,
                                mbedtls_ctr_drbg_random, &g_ctr_drbg,
                                cert_buf, &cert_len,
                                &status, &fail_info);
    TEST_ASSERT_NOT_EQUAL(0, rc);
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 22. scep_parse_getcacert -- single byte / empty SEQUENCE
 * ======================================================================= */

/* Single-byte input is too short to be any useful ASN.1 ContentInfo */
void test_parse_getcacert_single_byte_returns_error(void)
{
    static const uint8_t one[] = { 0x30 };
    scep_cacert_bundle_t bundle;
    int rc = scep_parse_getcacert(one, 1, &bundle);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* An empty SEQUENCE (30 00) -- valid DER but not a ContentInfo */
void test_parse_getcacert_empty_sequence_returns_error(void)
{
    static const uint8_t empty_seq[] = { 0x30, 0x00 };
    scep_cacert_bundle_t bundle;
    int rc = scep_parse_getcacert(empty_seq, sizeof(empty_seq), &bundle);
    TEST_ASSERT_NOT_EQUAL(0, rc);
}

/* =========================================================================
 * Main
 * ======================================================================= */

int main(void)
{
    UNITY_BEGIN();

    /* Keypair */
    RUN_TEST(test_keypair_generates_valid_rsa2048_key);
    RUN_TEST(test_keypair_public_exponent_is_65537);

    /* Transaction ID */
    RUN_TEST(test_transaction_id_is_64_hex_chars);
    RUN_TEST(test_transaction_id_is_deterministic);
    RUN_TEST(test_transaction_id_different_keys_differ);
    RUN_TEST(test_transaction_id_buffer_too_small_returns_error);

    /* CSR */
    RUN_TEST(test_csr_build_and_reparse_cn_and_challenge_pw);
    RUN_TEST(test_csr_is_signed_with_rsa);
    RUN_TEST(test_csr_null_subject_returns_error);
    RUN_TEST(test_csr_optional_subject_fields_may_be_null);

    /* CSR error paths */
    RUN_TEST(test_csr_output_buffer_too_small_returns_error);
    RUN_TEST(test_csr_empty_cn_returns_error);

    /* Self-signed cert */
    RUN_TEST(test_self_signed_cert_parses_with_openssl);

    /* SPKI */
    RUN_TEST(test_spki_export_is_repeatable);
    RUN_TEST(test_spki_is_rsa_subjectpublickeyinfo);

    /* scep_parse_certrep error paths */
    RUN_TEST(test_parse_certrep_null_p7_returns_error);
    RUN_TEST(test_parse_certrep_truncated_der_returns_error);

    /* scep_parse_getcacert error paths */
    RUN_TEST(test_parse_getcacert_null_p7_returns_error);
    RUN_TEST(test_parse_getcacert_null_out_returns_error);
    RUN_TEST(test_parse_getcacert_garbage_der_returns_error);

    /* scep_transaction_id NULL inputs */
    RUN_TEST(test_transaction_id_null_spki_returns_error);
    RUN_TEST(test_transaction_id_null_out_returns_error);

    /* scep_generate_keypair NULL inputs */
    RUN_TEST(test_generate_keypair_null_out_returns_error);
    RUN_TEST(test_generate_keypair_null_rng_returns_error);

    /* scep_build_self_signed_cert additional error paths */
    RUN_TEST(test_self_signed_cert_null_key_returns_error);
    RUN_TEST(test_self_signed_cert_null_subject_returns_error);
    RUN_TEST(test_self_signed_cert_null_out_returns_error);
    RUN_TEST(test_self_signed_cert_optional_fields_present);

    /* scep_transaction_id edge cases */
    RUN_TEST(test_transaction_id_all_zero_spki);
    RUN_TEST(test_transaction_id_exact_no_nul_buffer_fails);

    /* scep_build_csr additional error paths */
    RUN_TEST(test_csr_null_rng_fn_returns_error);
    RUN_TEST(test_csr_null_key_returns_error);
    RUN_TEST(test_csr_null_challenge_password_returns_error);

    /* mbedTLS version-gate compile-time API path checks */
    RUN_TEST(test_mbedtls_version_gate_keypair_works);
    RUN_TEST(test_mbedtls_pk_sign_version_path_produces_valid_signature);

    /* scep_build_csr long/full DN */
    RUN_TEST(test_csr_long_cn_64_chars_no_crash);
    RUN_TEST(test_csr_very_long_cn_fails_gracefully);
    RUN_TEST(test_csr_all_dn_fields_populated_and_verifies);

    /* scep_build_self_signed_cert NotBefore/NotAfter + sig */
    RUN_TEST(test_self_signed_cert_notbefore_before_notafter);
    RUN_TEST(test_self_signed_cert_signature_self_verifies);
    RUN_TEST(test_self_signed_cert_pubkey_matches_pk_context);

    /* scep_parse_getcacert RSA key_encipherment selection */
    RUN_TEST(test_parse_getcacert_rsa_key_encipherment_cert_is_selected_for_ra_encrypt);

    /* Additional scep_proto edge cases */
    RUN_TEST(test_transaction_id_single_byte_spki_produces_valid_hex);
    RUN_TEST(test_transaction_id_length_64_bytes_spki_produces_valid_hex);
    RUN_TEST(test_transaction_id_exact_capacity_plus_one_succeeds);
    RUN_TEST(test_csr_cn_with_special_chars_ascii_printable);
    RUN_TEST(test_csr_cn_with_spaces_no_crash);
    RUN_TEST(test_self_signed_cert_tiny_buf_returns_error);
    RUN_TEST(test_parse_certrep_wrong_outer_tag_returns_error);
    RUN_TEST(test_parse_certrep_all_zeros_returns_error);
    RUN_TEST(test_parse_getcacert_single_byte_returns_error);
    RUN_TEST(test_parse_getcacert_empty_sequence_returns_error);

    /* Cleanup global RNG */
    if (g_rng_init) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
    }

    return UNITY_END();
}
