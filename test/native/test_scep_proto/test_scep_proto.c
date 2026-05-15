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

    /* Cleanup global RNG */
    if (g_rng_init) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
    }

    return UNITY_END();
}
