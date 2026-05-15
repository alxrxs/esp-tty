/*
 * test_scep_proto_smoke.c -- on-device smoke test for lib/scep_proto
 *
 * Path 3b: on-device embedded Unity test (not run in normal CI).
 *
 * Rationale for choosing 3b over 3a (C harness for Python KAT):
 *   The scep_proto functions that do PKCS#7 (scep_build_pkimessage_pkcsreq,
 *   scep_parse_certrep, scep_parse_getcacert) depend on wolfSSL's wc_PKCS7_*
 *   engine.  The native test build uses OpenSSL-backed stubs for wolfCrypt
 *   primitives (ECC keygen, SHA-256, ASN.1 cert/CSR build), but the PKCS7
 *   API is NOT stubbed -- implementing faithful PKCS7 wrappers in the stub
 *   layer would duplicate the library under test, defeating the purpose.
 *
 *   A C CLI harness (3a) would have the same problem: it could only exercise
 *   the non-PKCS7 functions natively, which the existing native unit tests
 *   (test_scep_proto) already cover comprehensively.
 *
 *   The on-device smoke test runs on the actual wolfSSL + hardware RNG and
 *   verifies the full round-trip: keygen -> CSR -> self-signed cert ->
 *   PKCSReq pkiMessage -> (self-parse with SCEP_PROTO_TEST_HELPERS) ->
 *   verify extracted CSR and signed attributes.
 *
 * Build gate:
 *   Gated on SCEP_SMOKE_TEST being defined.  Not built in normal CI.
 *   To run on device:
 *     venv/bin/pio test -e esp32s3 -f embedded/test_scep_proto_smoke
 *   (requires SCEP_SMOKE_TEST=1 in build_flags or extra_build_flags).
 *
 * wolfSSL features required (must be in user_settings.h):
 *   HAVE_PKCS7, WOLFSSL_CERT_GEN, WOLFSSL_CERT_REQ, HAVE_AES_CBC
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifdef SCEP_SMOKE_TEST

#include "unity.h"
#include "scep_proto.h"

#include <string.h>
#include <stdio.h>

/* ---- helpers ---- */

static WC_RNG  g_rng;
static ecc_key g_key;

static void setup_key(void)
{
    int rc = wc_InitRng(&g_rng);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "wc_InitRng");
    rc = scep_generate_keypair(&g_key, &g_rng);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_generate_keypair");
}

static void teardown_key(void)
{
    wc_ecc_free(&g_key);
    wc_FreeRng(&g_rng);
}

void setUp(void)    { setup_key(); }
void tearDown(void) { teardown_key(); }

/* ---- test 1: transaction ID from SPKI ---- */
void test_transaction_id_length(void)
{
    uint8_t spki[256];
    int spki_len = wc_EccPublicKeyToDer(&g_key, spki, sizeof(spki), 1);
    TEST_ASSERT_GREATER_THAN_INT(0, spki_len);

    char tid[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    int rc = scep_transaction_id(spki, (size_t)spki_len, tid, sizeof(tid));
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_EQUAL_size_t(SCEP_TRANSACTION_ID_HEX_LEN, strlen(tid));

    /* Must be lowercase hex */
    for (size_t i = 0; i < SCEP_TRANSACTION_ID_HEX_LEN; i++) {
        char c = tid[i];
        TEST_ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

/* ---- test 2: CSR build with challenge password ---- */
void test_csr_build_succeeds(void)
{
    scep_subject_t subj = {
        .common_name  = "esp-tty-smoke-test",
        .organization = "TestOrg",
        .country      = "RO",
    };
    const char *challenge = "FFC9708138742EC99A8CDF837A9F4CEA";

    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);

    int rc = scep_build_csr(&subj, &g_key, challenge, csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_csr");
    TEST_ASSERT_GREATER_THAN_size_t(64, csr_len);

    /* CSR must begin with a SEQUENCE tag (0x30) */
    TEST_ASSERT_EQUAL_HEX8(0x30, csr_der[0]);
}

/* ---- test 3: self-signed cert build ---- */
void test_self_signed_cert_build(void)
{
    scep_subject_t subj = {
        .common_name = "esp-tty-smoke-test",
    };

    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);

    int rc = scep_build_self_signed_cert(&subj, &g_key, &g_rng,
                                          cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_self_signed_cert");
    TEST_ASSERT_GREATER_THAN_size_t(100, cert_len);

    /* Cert must begin with a SEQUENCE tag (0x30) */
    TEST_ASSERT_EQUAL_HEX8(0x30, cert_der[0]);
}

/* ---- test 4: PKCSReq roundtrip (build then self-parse) ---- */
void test_pkcsreq_roundtrip(void)
{
    const char *challenge = "FFC9708138742EC99A8CDF837A9F4CEA";

    /* Build CSR */
    scep_subject_t subj = { .common_name = "smoke-roundtrip" };
    uint8_t csr_der[SCEP_MAX_CSR_DER];
    size_t  csr_len = sizeof(csr_der);
    int rc = scep_build_csr(&subj, &g_key, challenge, csr_der, &csr_len);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Build self-signed cert */
    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);
    rc = scep_build_self_signed_cert(&subj, &g_key, &g_rng, cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Derive transactionID */
    uint8_t spki[256];
    int spki_len = wc_EccPublicKeyToDer(&g_key, spki, sizeof(spki), 1);
    TEST_ASSERT_GREATER_THAN_INT(0, spki_len);
    char tid[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
    scep_transaction_id(spki, (size_t)spki_len, tid, sizeof(tid));

    /* Build PKCSReq pkiMessage (self-addressed: RA cert == self-signed cert) */
    uint8_t p7_buf[SCEP_MAX_P7_LEN];
    size_t  p7_len = sizeof(p7_buf);
    rc = scep_build_pkimessage_pkcsreq(
        csr_der, csr_len,
        cert_der, cert_len,       /* RA cert == self for smoke test */
        &g_key,
        cert_der, cert_len,       /* signer cert */
        &g_rng,
        tid,
        p7_buf, &p7_len
    );
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_build_pkimessage_pkcsreq");
    TEST_ASSERT_GREATER_THAN_size_t(100, p7_len);

    /* Self-parse with the test helper (if built with SCEP_PROTO_TEST_HELPERS) */
#ifdef SCEP_PROTO_TEST_HELPERS
    scep_pkcsreq_unpacked_t unpacked;
    rc = scep_parse_pkimessage_pkcsreq_for_test(
        p7_buf, p7_len,
        &g_key,
        cert_der, cert_len,
        &unpacked
    );
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_parse_pkimessage_pkcsreq_for_test");

    /* Verify message type */
    TEST_ASSERT_EQUAL_STRING("19", unpacked.message_type);

    /* Verify transactionID round-trips */
    TEST_ASSERT_EQUAL_STRING(tid, unpacked.transaction_id);

    /* Verify CSR is present */
    TEST_ASSERT_GREATER_THAN_size_t(0, unpacked.csr_len);
    TEST_ASSERT_EQUAL_HEX8(0x30, unpacked.csr_der[0]);

    printf("[smoke] roundtrip OK: tid=%s csr_len=%zu\n",
           unpacked.transaction_id, unpacked.csr_len);
#else
    /* Without SCEP_PROTO_TEST_HELPERS, just verify the built message is
     * a valid DER SEQUENCE. */
    TEST_ASSERT_EQUAL_HEX8(0x30, p7_buf[0]);
    printf("[smoke] pkiMessage built OK (%zu bytes), no self-parse (need SCEP_PROTO_TEST_HELPERS)\n",
           p7_len);
#endif
}

/* ---- test 5: GetCACert single-cert parse ---- */
void test_getcacert_parse_single_cert(void)
{
    /* Build a self-signed cert to use as a degenerate CA bundle */
    scep_subject_t subj = { .common_name = "fake-ca" };
    uint8_t cert_der[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_der);
    int rc = scep_build_self_signed_cert(&subj, &g_key, &g_rng,
                                          cert_der, &cert_len);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Wrap the cert in a degenerate PKCS#7 SignedData.
     *
     * We build the minimal degenerate structure by hand:
     * ContentInfo { OID(signedData), [0] SignedData {
     *   version=1, digestAlgs={}, encapContent={OID(data)},
     *   [0] certs { cert_der }, signerInfos={}
     * }}
     *
     * This mirrors what NDES returns for GetCACert with a single CA cert.
     *
     * We use a wc_PKCS7 degenerate approach: init, set cert, encode.
     */
    wc_PKCS7 p7;
    rc = wc_PKCS7_Init(&p7, NULL, INVALID_DEVID);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = wc_PKCS7_InitWithCert(&p7, cert_der, (word32)cert_len);
    TEST_ASSERT_EQUAL_INT(0, rc);

    p7.contentOID = DATA;
    p7.hashOID    = SHA256h;
    p7.encryptOID = ECDSAk;
    p7.content    = (byte *)"";
    p7.contentSz  = 0;

    uint8_t p7_buf[SCEP_MAX_CA_BUNDLE_CERT_DER + 512];
    int p7_sz = wc_PKCS7_EncodeSignedData_ex(&p7, NULL, 0, p7_buf, sizeof(p7_buf));
    wc_PKCS7_Free(&p7);

    if (p7_sz <= 0) {
        /* Some wolfSSL builds don't support unsigned SignedData (no signer). */
        TEST_IGNORE_MESSAGE("wc_PKCS7_EncodeSignedData_ex returned no output "
                             "(may need SCEP_PROTO_TEST_HELPERS or unsigned SD support); skipping");
        return;
    }

    scep_cacert_bundle_t bundle;
    rc = scep_parse_getcacert(p7_buf, (size_t)p7_sz, &bundle);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "scep_parse_getcacert");
    TEST_ASSERT_NOT_NULL(bundle.ca_cert_der);
    TEST_ASSERT_GREATER_THAN_size_t(0, bundle.ca_cert_len);
    TEST_ASSERT_EQUAL_INT(1, bundle.single_cert);

    /* All three pointers should be the same (single cert) */
    TEST_ASSERT_EQUAL_PTR(bundle.ca_cert_der, bundle.ra_sign_cert_der);
    TEST_ASSERT_EQUAL_PTR(bundle.ca_cert_der, bundle.ra_encrypt_cert_der);
}

/* ---- main ---- */
void app_main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_transaction_id_length);
    RUN_TEST(test_csr_build_succeeds);
    RUN_TEST(test_self_signed_cert_build);
    RUN_TEST(test_pkcsreq_roundtrip);
    RUN_TEST(test_getcacert_parse_single_cert);
    UNITY_END();
}

#else /* SCEP_SMOKE_TEST not defined */

/*
 * Stub main so the test file compiles even without the gate flag.
 * The test runner will see zero test cases.
 */
void app_main(void)
{
    /* Smoke tests disabled: define SCEP_SMOKE_TEST=1 in build_flags to enable.
     * See test/embedded/test_scep_proto_smoke/test_scep_proto_smoke.c. */
}

#endif /* SCEP_SMOKE_TEST */
