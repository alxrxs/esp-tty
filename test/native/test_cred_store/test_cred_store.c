/*
 * test_cred_store.c -- native unit tests for cred_store
 *
 * Tests:
 *   1. cred_store_parse_not_after() with a real DER fixture (RSA-2048 cert,
 *      NotAfter = 2036-05-13 05:04:11 UTC -> epoch 2094267851).
 *   2. cred_store_load() returns NOT_FOUND when store is empty.
 *   3. cred_store_save() + cred_store_load() round-trip.
 *   4. cred_store_clear() resets the store.
 *   5. parse_not_after NULL / empty input -> ESP_ERR_INVALID_ARG.
 *   6. parse_not_after with corrupted DER -> ESP_FAIL.
 *   7. save/load preserves all four fields (dev_key, dev_cert, ca_chain,
 *      not_after) exactly.
 *
 * Compiled with -DCRED_STORE_NATIVE_TEST (in-memory NVS backend) and
 * -DUNIT_TEST (suppress ESP_LOG colour codes, already handled by stub).
 *
 * Linked against OpenSSL 3 (-lcrypto) via the wolfSSL ASN1 stubs in
 * test/stubs/wolfssl/wolfcrypt/asn_public.h.
 */

#define CRED_STORE_NATIVE_TEST  1

#include "unity.h"
#include "cred_store.h"

#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

/* --------------------------------------------------------------------------
 * Fixture: RSA-2048 self-signed cert, NotAfter = 2036-05-13 05:04:11 UTC
 *          Generated with: openssl req -x509 -newkey rsa:2048 -days 3652
 *            -noenc -subj "/CN=test-device"
 *          Key algorithm changed from ECDSA P-256 to RSA-2048 because
 *          NDES in legacy CryptoAPI/CSP mode requires RSA (RFC 8894 §3.5.2).
 * -------------------------------------------------------------------------- */
static const uint8_t fixture_cert_der[] = {
    0x30, 0x82, 0x03, 0x0d, 0x30, 0x82, 0x01, 0xf5, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x68, 0x62, 0x5f, 0x19, 0x48, 0xc4, 0x00, 0xec, 0x73,
    0xf2, 0x13, 0x8b, 0x5d, 0x94, 0x18, 0x34, 0x03, 0x70, 0x15, 0x51, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x65, 0x76, 0x69,
    0x63, 0x65, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x35, 0x31, 0x34,
    0x30, 0x35, 0x30, 0x34, 0x31, 0x31, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30,
    0x35, 0x31, 0x33, 0x30, 0x35, 0x30, 0x34, 0x31, 0x31, 0x5a, 0x30, 0x16,
    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x74,
    0x65, 0x73, 0x74, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x82,
    0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
    0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb1, 0xa1, 0x23, 0x82, 0x16,
    0x6d, 0xca, 0x2b, 0x98, 0x0b, 0x97, 0xad, 0x55, 0x61, 0x60, 0xf9, 0xe2,
    0x1e, 0xca, 0xeb, 0xdf, 0x4d, 0xb0, 0xd2, 0x45, 0x07, 0x29, 0xa5, 0xd9,
    0x7f, 0x41, 0x9d, 0x62, 0x80, 0x69, 0x95, 0x81, 0xaa, 0x01, 0x9b, 0xeb,
    0x81, 0x21, 0xf0, 0x03, 0xd9, 0x53, 0xa6, 0xf0, 0x87, 0x30, 0xc7, 0x1a,
    0x22, 0x4b, 0x7c, 0x1d, 0xd1, 0xa0, 0xe8, 0x46, 0x44, 0x0c, 0x93, 0xd4,
    0x1d, 0xb0, 0xb1, 0x12, 0x5c, 0x7f, 0x65, 0x5a, 0xf9, 0xc8, 0xfb, 0x03,
    0x8d, 0x00, 0x2d, 0xdc, 0xca, 0xf7, 0x28, 0xc3, 0x7d, 0x43, 0x49, 0xa8,
    0x4c, 0x84, 0x5a, 0xeb, 0xde, 0x78, 0x7b, 0xa5, 0xb9, 0xf0, 0xe0, 0xdb,
    0x0d, 0xe8, 0xe9, 0xf4, 0xfe, 0x9a, 0x85, 0x1e, 0x03, 0xdb, 0x1e, 0x80,
    0x74, 0x3f, 0x95, 0x67, 0xf1, 0x1f, 0x50, 0xc5, 0xb6, 0xad, 0x50, 0xc1,
    0xb3, 0x65, 0x43, 0x50, 0x3c, 0x83, 0x41, 0x1c, 0x30, 0x81, 0x8d, 0x7e,
    0xcb, 0xc5, 0xcd, 0xf2, 0xc5, 0x1e, 0x31, 0x54, 0xb9, 0x50, 0x5c, 0x26,
    0xdd, 0x86, 0x4c, 0x8a, 0x0e, 0x6e, 0xe5, 0x82, 0x2d, 0x3b, 0x91, 0x3a,
    0x8f, 0xdb, 0x80, 0x44, 0x79, 0xae, 0xdb, 0x05, 0xc9, 0xd2, 0x0d, 0x3d,
    0x33, 0x56, 0x69, 0x69, 0x7e, 0x29, 0x07, 0xb1, 0x80, 0x75, 0x15, 0x9a,
    0x0a, 0x43, 0x0d, 0x80, 0x78, 0x6e, 0x17, 0x13, 0x5c, 0x61, 0x82, 0x06,
    0xe5, 0x03, 0x85, 0x1b, 0xdb, 0x26, 0xed, 0x36, 0x18, 0xec, 0x12, 0xbc,
    0x4d, 0x91, 0xa2, 0x08, 0x2a, 0x50, 0xec, 0xc6, 0x21, 0x9f, 0xb8, 0x55,
    0xbf, 0xd1, 0x7a, 0x5c, 0x04, 0x30, 0x25, 0x90, 0xa9, 0xb6, 0x93, 0x9d,
    0xd9, 0xbb, 0xf1, 0xd6, 0xb6, 0x9e, 0x25, 0x1c, 0x7b, 0x96, 0x87, 0xc0,
    0x88, 0xaa, 0x0f, 0x0e, 0x0f, 0x0f, 0x5a, 0x63, 0xe6, 0x42, 0xff, 0x02,
    0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x5d, 0x25, 0xb8, 0xe3, 0x9c,
    0x87, 0x12, 0x77, 0x28, 0xfa, 0x18, 0x10, 0xf7, 0x88, 0x1b, 0x9a, 0x3b,
    0x1f, 0x36, 0x17, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0x5d, 0x25, 0xb8, 0xe3, 0x9c, 0x87, 0x12, 0x77,
    0x28, 0xfa, 0x18, 0x10, 0xf7, 0x88, 0x1b, 0x9a, 0x3b, 0x1f, 0x36, 0x17,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
    0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,
    0x00, 0x10, 0x8b, 0xfb, 0x13, 0xcc, 0xee, 0xc3, 0x47, 0xad, 0x0d, 0x21,
    0x51, 0xe3, 0xc0, 0x54, 0xd8, 0x73, 0x60, 0x55, 0x08, 0x6e, 0x22, 0x5a,
    0x5a, 0x8d, 0x4a, 0x27, 0xbe, 0x95, 0xd3, 0xb4, 0x64, 0x66, 0x9c, 0xea,
    0xa9, 0xe2, 0x36, 0x25, 0x09, 0xeb, 0xf6, 0xc2, 0x17, 0x78, 0xb6, 0x92,
    0xc7, 0x94, 0xcb, 0xed, 0xb6, 0x15, 0x38, 0xe0, 0xd2, 0x86, 0xc3, 0x7b,
    0x86, 0x7f, 0xd1, 0x48, 0x00, 0x48, 0x37, 0x22, 0x34, 0x61, 0xa7, 0xd9,
    0x59, 0xeb, 0x66, 0xee, 0xc0, 0x45, 0xbf, 0xb1, 0x12, 0xd6, 0x7d, 0xd0,
    0xac, 0xd2, 0x05, 0x19, 0xfc, 0x53, 0x6b, 0xbd, 0x94, 0x04, 0x27, 0x5f,
    0x93, 0xa1, 0xf1, 0x2f, 0x6a, 0xf7, 0x32, 0x49, 0x77, 0x6f, 0xe9, 0xf1,
    0xb4, 0x07, 0x08, 0x6a, 0xf9, 0xad, 0x01, 0xea, 0x4d, 0xa6, 0x82, 0x8f,
    0x4e, 0x31, 0xf8, 0xbc, 0xbf, 0xdf, 0xa6, 0x17, 0x4c, 0xeb, 0xd3, 0xf4,
    0xd5, 0xd7, 0x74, 0x94, 0x18, 0x24, 0x8b, 0xe8, 0xc6, 0x9e, 0x90, 0x0c,
    0xd6, 0x6c, 0x86, 0x0c, 0xe3, 0x3e, 0x2d, 0xc1, 0xa8, 0x22, 0xec, 0x96,
    0xe6, 0x97, 0xbc, 0xac, 0xfc, 0xbd, 0xd0, 0xff, 0x9c, 0xaf, 0xc8, 0xb1,
    0x8e, 0x81, 0x0d, 0x84, 0x13, 0xa7, 0x0a, 0x41, 0xeb, 0x6b, 0x31, 0xae,
    0x46, 0xa0, 0x27, 0x61, 0xca, 0x1d, 0xa9, 0xae, 0x76, 0x29, 0xf7, 0xe9,
    0x60, 0xf3, 0x8a, 0xf1, 0x18, 0x1a, 0x1a, 0xad, 0xca, 0xd0, 0x7a, 0xbb,
    0x8e, 0x01, 0x64, 0x5b, 0x83, 0xad, 0x8e, 0x99, 0xc4, 0x27, 0x61, 0x47,
    0x16, 0x48, 0x34, 0x0c, 0x8f, 0x42, 0x0b, 0xa2, 0x98, 0x00, 0x1c, 0xf5,
    0x27, 0xbe, 0x32, 0x7c, 0x86, 0x75, 0x4d, 0xd0, 0x33, 0x95, 0x0f, 0x1f,
    0x9f, 0x3e, 0x91, 0xe2, 0x34, 0x25, 0x0b, 0xc0, 0x8d, 0xf4, 0xd3, 0x2f,
    0xe1, 0x1d, 0x8e, 0x8e, 0x3e
};
static const size_t fixture_cert_der_len = 785;

/* Expected NotAfter epoch: 2036-05-13 05:04:11 UTC */
#define FIXTURE_NOT_AFTER_EPOCH  UINT64_C(2094267851)

/* --------------------------------------------------------------------------
 * setUp / tearDown -- reset the in-memory store before each test
 * -------------------------------------------------------------------------- */
void setUp(void)
{
    cred_store_clear();
}

void tearDown(void) {}

/* --------------------------------------------------------------------------
 * Test 1: parse_not_after returns correct epoch for the fixture cert
 * -------------------------------------------------------------------------- */
static void test_parse_not_after_correct_epoch(void)
{
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_after(fixture_cert_der,
                                               fixture_cert_der_len,
                                               &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_OK, err);
    TEST_ASSERT_EQUAL_UINT64(FIXTURE_NOT_AFTER_EPOCH, epoch);
}

/* --------------------------------------------------------------------------
 * Test 2: load on empty store returns ESP_ERR_NVS_NOT_FOUND
 * -------------------------------------------------------------------------- */
static void test_load_empty_returns_not_found(void)
{
    cred_store_t cs;
    esp_err_t err = cred_store_load(&cs);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, err);
}

/* --------------------------------------------------------------------------
 * Test 3: save then load round-trips all fields
 * -------------------------------------------------------------------------- */
static void test_save_load_roundtrip(void)
{
    /* Build a cred_store_t with recognizable data. */
    cred_store_t in;
    memset(&in, 0, sizeof(in));

    /* Fake device key: 32 bytes ascending */
    in.dev_key_len = 32;
    for (size_t i = 0; i < 32; i++) in.dev_key[i] = (uint8_t)i;

    /* Fake device cert: the fixture DER */
    in.dev_cert_len = fixture_cert_der_len;
    memcpy(in.dev_cert, fixture_cert_der, fixture_cert_der_len);

    /* Fake CA chain: a short PEM-like string */
    const char *chain = "-----BEGIN CERTIFICATE-----\nABCDE\n-----END CERTIFICATE-----\n";
    in.ca_chain_len = strlen(chain);
    memcpy(in.ca_chain, chain, in.ca_chain_len);

    in.not_after = FIXTURE_NOT_AFTER_EPOCH;

    esp_err_t err = cred_store_save(&in);
    TEST_ASSERT_EQUAL_INT(ESP_OK, err);

    cred_store_t out;
    memset(&out, 0, sizeof(out));
    err = cred_store_load(&out);
    TEST_ASSERT_EQUAL_INT(ESP_OK, err);

    TEST_ASSERT_EQUAL_size_t(in.dev_key_len, out.dev_key_len);
    TEST_ASSERT_EQUAL_MEMORY(in.dev_key, out.dev_key, in.dev_key_len);

    TEST_ASSERT_EQUAL_size_t(in.dev_cert_len, out.dev_cert_len);
    TEST_ASSERT_EQUAL_MEMORY(in.dev_cert, out.dev_cert, in.dev_cert_len);

    TEST_ASSERT_EQUAL_size_t(in.ca_chain_len, out.ca_chain_len);
    TEST_ASSERT_EQUAL_MEMORY(in.ca_chain, out.ca_chain, in.ca_chain_len);

    TEST_ASSERT_EQUAL_UINT64(in.not_after, out.not_after);
}

/* --------------------------------------------------------------------------
 * Test 4: clear after save -> load returns NOT_FOUND
 * -------------------------------------------------------------------------- */
static void test_clear_after_save(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len  = 1; in.dev_key[0]  = 0xAA;
    in.dev_cert_len = 1; in.dev_cert[0] = 0xBB;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xCC;
    in.not_after    = 12345678;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));

    /* Verify it's there */
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));

    /* Now clear and verify it's gone */
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_clear());
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* --------------------------------------------------------------------------
 * Test 5: parse_not_after with NULL cert_der -> ESP_ERR_INVALID_ARG
 * -------------------------------------------------------------------------- */
static void test_parse_null_cert_returns_invalid_arg(void)
{
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_after(NULL, 100, &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

/* --------------------------------------------------------------------------
 * Test 6: parse_not_after with zero length -> ESP_ERR_INVALID_ARG
 * -------------------------------------------------------------------------- */
static void test_parse_zero_len_returns_invalid_arg(void)
{
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_after(fixture_cert_der, 0, &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

/* --------------------------------------------------------------------------
 * Test 7: parse_not_after with NULL out_epoch -> ESP_ERR_INVALID_ARG
 * -------------------------------------------------------------------------- */
static void test_parse_null_out_returns_invalid_arg(void)
{
    esp_err_t err = cred_store_parse_not_after(fixture_cert_der,
                                               fixture_cert_der_len, NULL);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

/* --------------------------------------------------------------------------
 * Test 8: parse_not_after with corrupted DER -> ESP_FAIL
 * -------------------------------------------------------------------------- */
static void test_parse_corrupted_der_returns_fail(void)
{
    /* Flip the first byte so the SEQUENCE tag is wrong. */
    uint8_t bad[785];
    memcpy(bad, fixture_cert_der, fixture_cert_der_len);
    bad[0] = 0xFF;

    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_after(bad, fixture_cert_der_len, &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, err);
}

/* --------------------------------------------------------------------------
 * Test 9: double save overwrites previous data
 * -------------------------------------------------------------------------- */
static void test_double_save_overwrites(void)
{
    cred_store_t a, b, out;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    a.dev_key_len = 1; a.dev_key[0] = 0x11;
    a.dev_cert_len = 1; a.dev_cert[0] = 0x22;
    a.ca_chain_len = 1; a.ca_chain[0] = 0x33;
    a.not_after = 111;

    b.dev_key_len = 2; b.dev_key[0] = 0xAA; b.dev_key[1] = 0xBB;
    b.dev_cert_len = 1; b.dev_cert[0] = 0xCC;
    b.ca_chain_len = 1; b.ca_chain[0] = 0xDD;
    b.not_after = 999;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&a));
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&b));
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));

    TEST_ASSERT_EQUAL_UINT64(999, out.not_after);
    TEST_ASSERT_EQUAL_size_t(2, out.dev_key_len);
    TEST_ASSERT_EQUAL_HEX8(0xAA, out.dev_key[0]);
}

/* --------------------------------------------------------------------------
 * Test 10: save(NULL) returns INVALID_ARG without modifying the store.
 * -------------------------------------------------------------------------- */
static void test_save_null_returns_invalid_arg(void)
{
    /* Pre-populate the store so we can verify it is unchanged afterwards. */
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0xAB;
    in.dev_cert_len = 1; in.dev_cert[0] = 0xCD;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xEF;
    in.not_after = 9999;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));

    esp_err_t err = cred_store_save(NULL);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);

    /* Store should still be intact. */
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_UINT64(9999, out.not_after);
}

/* --------------------------------------------------------------------------
 * Test 11: load(NULL) returns INVALID_ARG.
 * -------------------------------------------------------------------------- */
static void test_load_null_returns_invalid_arg(void)
{
    esp_err_t err = cred_store_load(NULL);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

/* --------------------------------------------------------------------------
 * Test 12: clear on an already-empty store succeeds (idempotent).
 * -------------------------------------------------------------------------- */
static void test_clear_on_empty_is_idempotent(void)
{
    /* setUp already called clear(), so store is empty. */
    esp_err_t err = cred_store_clear();
    TEST_ASSERT_EQUAL_INT(ESP_OK, err);

    /* Still not found. */
    cred_store_t cs;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&cs));
}

/* --------------------------------------------------------------------------
 * Test 13: not_after = 0 is stored and loaded exactly.
 *          (Callers use 0 as a sentinel for "expiry unknown"; verify it
 *          round-trips without being silently treated as missing.)
 * -------------------------------------------------------------------------- */
static void test_not_after_zero_is_preserved(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len  = 1; in.dev_key[0]  = 0x01;
    in.dev_cert_len = 1; in.dev_cert[0] = 0x02;
    in.ca_chain_len = 1; in.ca_chain[0] = 0x03;
    in.not_after = 0;   /* sentinel: expiry unknown */

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_UINT64(0, out.not_after);
}

/* --------------------------------------------------------------------------
 * Tests for cred_store_parse_not_before
 *
 * The fixture cert has NotBefore = 2026-05-14 05:04:11 UTC.
 * Compute: days_from_civil(2026, 5, 14) = epoch_days; add H:M:S.
 * 2026-05-14 05:04:11 UTC = 1747198651 seconds since 1970-01-01.
 * -------------------------------------------------------------------------- */
#define FIXTURE_NOT_BEFORE_EPOCH  UINT64_C(1778735051)

static void test_parse_not_before_correct_epoch(void)
{
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_before(fixture_cert_der,
                                                fixture_cert_der_len,
                                                &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_OK, err);
    TEST_ASSERT_EQUAL_UINT64(FIXTURE_NOT_BEFORE_EPOCH, epoch);
}

static void test_parse_not_before_null_cert_returns_invalid_arg(void)
{
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_before(NULL, 100, &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

static void test_parse_not_before_zero_len_returns_invalid_arg(void)
{
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_before(fixture_cert_der, 0, &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

static void test_parse_not_before_null_out_returns_invalid_arg(void)
{
    esp_err_t err = cred_store_parse_not_before(fixture_cert_der,
                                                fixture_cert_der_len, NULL);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_INVALID_ARG, err);
}

static void test_parse_not_before_corrupted_der_returns_fail(void)
{
    uint8_t bad[785];
    memcpy(bad, fixture_cert_der, fixture_cert_der_len);
    bad[0] = 0xFF;

    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_before(bad, fixture_cert_der_len, &epoch);
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, err);
}

/* NotBefore must be strictly earlier than NotAfter for a well-formed cert. */
static void test_parse_not_before_is_earlier_than_not_after(void)
{
    uint64_t not_before = 0;
    uint64_t not_after  = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK,
        cred_store_parse_not_before(fixture_cert_der, fixture_cert_der_len,
                                    &not_before));
    TEST_ASSERT_EQUAL_INT(ESP_OK,
        cred_store_parse_not_after(fixture_cert_der, fixture_cert_der_len,
                                   &not_after));
    TEST_ASSERT_TRUE(not_before < not_after);
}

/* --------------------------------------------------------------------------
 * Test: parse_x509_time routes correctly
 *
 * parse_x509_time(use_not_before=false) -> valid_to  -> NotAfter epoch
 * parse_x509_time(use_not_before=true)  -> valid_from -> NotBefore epoch
 *
 * Verify that both public wrappers extract *different* fields from the same
 * cert.  This would fail if the use_not_before flag were ignored.
 * -------------------------------------------------------------------------- */
static void test_parse_x509_time_not_after_ne_not_before(void)
{
    uint64_t not_after  = 0;
    uint64_t not_before = 0;

    TEST_ASSERT_EQUAL_INT(ESP_OK,
        cred_store_parse_not_after(fixture_cert_der, fixture_cert_der_len, &not_after));
    TEST_ASSERT_EQUAL_INT(ESP_OK,
        cred_store_parse_not_before(fixture_cert_der, fixture_cert_der_len, &not_before));

    /* The two fields must differ; if they are equal the flag is being ignored. */
    TEST_ASSERT_NOT_EQUAL(not_after, not_before);
    /* Sanity: not_after must equal the known fixture value. */
    TEST_ASSERT_EQUAL_UINT64(FIXTURE_NOT_AFTER_EPOCH, not_after);
    /* Sanity: not_before must equal the known fixture value. */
    TEST_ASSERT_EQUAL_UINT64(FIXTURE_NOT_BEFORE_EPOCH, not_before);
}

/* --------------------------------------------------------------------------
 * Test: max-length dev_key (CRED_DEV_KEY_MAX bytes) is preserved
 * -------------------------------------------------------------------------- */
static void test_max_dev_key_preserves_all_bytes(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = CRED_DEV_KEY_MAX;
    for (size_t i = 0; i < CRED_DEV_KEY_MAX; i++)
        in.dev_key[i] = (uint8_t)(i ^ 0xA5);
    in.dev_cert_len = 1; in.dev_cert[0] = 0x01;
    in.ca_chain_len = 1; in.ca_chain[0] = 0x02;
    in.not_after    = 9999;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));
    cred_store_t out;
    memset(&out, 0, sizeof(out));
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_size_t(CRED_DEV_KEY_MAX, out.dev_key_len);
    TEST_ASSERT_EQUAL_MEMORY(in.dev_key, out.dev_key, CRED_DEV_KEY_MAX);
}

/* --------------------------------------------------------------------------
 * Test: max-length dev_cert (CRED_DEV_CERT_MAX bytes) is preserved
 * -------------------------------------------------------------------------- */
static void test_max_dev_cert_preserves_all_bytes(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0x01;
    in.dev_cert_len = CRED_DEV_CERT_MAX;
    for (size_t i = 0; i < CRED_DEV_CERT_MAX; i++)
        in.dev_cert[i] = (uint8_t)(i ^ 0x5A);
    in.ca_chain_len = 1; in.ca_chain[0] = 0x02;
    in.not_after = 1234567890;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));
    cred_store_t out;
    memset(&out, 0, sizeof(out));
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_size_t(CRED_DEV_CERT_MAX, out.dev_cert_len);
    TEST_ASSERT_EQUAL_MEMORY(in.dev_cert, out.dev_cert, CRED_DEV_CERT_MAX);
}

/* --------------------------------------------------------------------------
 * Test: ca_chain of length 1 (minimum non-empty) round-trips
 * -------------------------------------------------------------------------- */
static void test_min_ca_chain_one_byte_roundtrips(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0x10;
    in.dev_cert_len = 1; in.dev_cert[0] = 0x20;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xAB;
    in.not_after = 42;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));
    cred_store_t out;
    memset(&out, 0, sizeof(out));
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_size_t(1, out.ca_chain_len);
    TEST_ASSERT_EQUAL_HEX8(0xAB, out.ca_chain[0]);
}

/* --------------------------------------------------------------------------
 * Test: parse_not_after on a 1-byte input returns FAIL (too short to be valid DER)
 * -------------------------------------------------------------------------- */
static void test_parse_not_after_one_byte_returns_fail(void)
{
    static const uint8_t one_byte[] = { 0x30 };
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_after(one_byte, 1, &epoch);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, err);
}

/* --------------------------------------------------------------------------
 * Test: parse_not_after on random-looking bytes returns FAIL
 * -------------------------------------------------------------------------- */
static void test_parse_not_after_garbage_returns_fail(void)
{
    static const uint8_t garbage[] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
    };
    uint64_t epoch = 0;
    esp_err_t err = cred_store_parse_not_after(garbage, sizeof(garbage), &epoch);
    TEST_ASSERT_NOT_EQUAL(ESP_OK, err);
}

/* --------------------------------------------------------------------------
 * Test: multiple sequential clears are all idempotent (returns ESP_OK each time)
 * -------------------------------------------------------------------------- */
static void test_multiple_clears_all_idempotent(void)
{
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_clear());
    }
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* --------------------------------------------------------------------------
 * Test: not_after UINT64_MAX is stored and loaded exactly (boundary sentinel)
 * -------------------------------------------------------------------------- */
static void test_not_after_uint64_max_preserved(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0x01;
    in.dev_cert_len = 1; in.dev_cert[0] = 0x02;
    in.ca_chain_len = 1; in.ca_chain[0] = 0x03;
    in.not_after = UINT64_MAX;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));
    cred_store_t out;
    memset(&out, 0, sizeof(out));
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, out.not_after);
}

/* --------------------------------------------------------------------------
 * Atomicity / schema version tests (B3)
 *
 * The native backend mirrors the device's "valid marker written last,
 * schema version checked on load" scheme.  The test-only fault-injection
 * hooks below simulate a power-fail between blob writes and the final
 * marker commit; load() must return NOT_FOUND.
 * -------------------------------------------------------------------------- */
extern void cred_store_testhook_partial_write(const cred_store_t *in);
extern void cred_store_testhook_force_schema(uint8_t schema);
extern void cred_store_testhook_schema_absent(const cred_store_t *in);
extern void cred_store_testhook_partial_clear(void);
extern void cred_store_testhook_save_partial_committed_blobs_no_marker(const cred_store_t *in);
extern void cred_store_testhook_save_fail_with_scrub(void);
extern void cred_store_testhook_clear_after_marker(void);
extern void cred_store_testhook_clear_after_scrub(void);
extern const uint8_t *cred_store_testhook_inspect_dev_key(void);

static void test_atomicity_partial_write_returns_not_found(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0xA1;
    in.dev_cert_len = 1; in.dev_cert[0] = 0xA2;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xA3;
    in.not_after = 1700000000;

    /* Simulate: blobs written + committed but valid marker never landed. */
    cred_store_testhook_partial_write(&in);

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

static void test_atomicity_full_save_loads_ok(void)
{
    /* Sanity: a full save() does set the marker and load() succeeds. */
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0xB1;
    in.dev_cert_len = 1; in.dev_cert[0] = 0xB2;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xB3;
    in.not_after = 1800000000;

    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));
    TEST_ASSERT_EQUAL_UINT64(1800000000, out.not_after);
}

static void test_schema_version_mismatch_returns_not_found(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0xC1;
    in.dev_cert_len = 1; in.dev_cert[0] = 0xC2;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xC3;
    in.not_after = 1900000000;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));

    /* Verify base case loads. */
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));

    /* Force a different schema version (simulating older-firmware rollback). */
    cred_store_testhook_force_schema(99);
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

static void test_schema_version_zero_returns_not_found(void)
{
    /* schema==0 must not be accepted (it is the post-clear value). */
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = 1; in.dev_key[0] = 0x01;
    in.dev_cert_len = 1; in.dev_cert[0] = 0x02;
    in.ca_chain_len = 1; in.ca_chain[0] = 0x03;
    in.not_after = 42;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));

    cred_store_testhook_force_schema(0);
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* --------------------------------------------------------------------------
 * L3.C schema_ver-absent test
 *
 * Simulates an older firmware that wrote the valid marker and blobs but
 * never wrote the schema_ver key (the key did not exist in that firmware
 * version).  cred_store_load() must return ESP_ERR_NVS_NOT_FOUND so that
 * newer firmware forces a fresh re-enrollment rather than mis-parsing blobs
 * whose layout may differ from CRED_SCHEMA_VERSION.
 *
 * This test exercises the ABSENT-key path (schema_ver never written),
 * in contrast to test_schema_version_mismatch_returns_not_found() which
 * tests the WRONG-VALUE path (key present but != CRED_SCHEMA_VERSION).
 * On the device-side NVS backend these are distinct code paths:
 *   absent -> nvs_get_u8 returns ESP_ERR_NVS_NOT_FOUND (err != ESP_OK)
 *   wrong  -> nvs_get_u8 returns ESP_OK but schema != CRED_SCHEMA_VERSION
 * The in-memory backend represents both as s_mem_schema == 0; the single
 * load() condition "err != ESP_OK || schema != CRED_SCHEMA_VERSION" covers
 * both cases identically, which is the correct behaviour.
 * -------------------------------------------------------------------------- */
static void test_schema_absent_returns_not_found(void)
{
    /* Build a cred_store_t representing an older firmware's saved state:
     * blobs populated, valid marker set, but schema_ver never written. */
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len  = 4;
    in.dev_key[0] = 0xDE; in.dev_key[1] = 0xAD;
    in.dev_key[2] = 0xBE; in.dev_key[3] = 0xEF;
    in.dev_cert_len = fixture_cert_der_len;
    memcpy(in.dev_cert, fixture_cert_der, fixture_cert_der_len);
    in.ca_chain_len = 1; in.ca_chain[0] = 0xCA;
    in.not_after = FIXTURE_NOT_AFTER_EPOCH;

    /* Inject the "schema_ver absent" state: valid marker present, blobs
     * present, but schema_ver key was never written (s_mem_schema == 0). */
    cred_store_testhook_schema_absent(&in);

    /* Newer firmware must refuse to load -- re-enrollment required. */
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* --------------------------------------------------------------------------
 * C2.C scrub-on-clear / scrub-on-save-fail tests
 *
 * Verify that after every power-fail boundary in cred_store_clear() AND in
 * the cred_store_save() error path:
 *   1. cred_store_load() returns ESP_ERR_NVS_NOT_FOUND, AND
 *   2. the in-memory backing store contains NO key DER fragments (all
 *      bytes of dev_key are zero).
 *
 * These tests use a recognisable non-zero key pattern so a missed scrub
 * point would leave the pattern bytes visible.
 * -------------------------------------------------------------------------- */

/* Seed the store with a recognisable key pattern that load() would accept. */
static void seed_store_with_key_pattern(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len = CRED_DEV_KEY_MAX;
    for (size_t i = 0; i < CRED_DEV_KEY_MAX; i++)
        in.dev_key[i] = (uint8_t)((i * 31 + 7) & 0xFF) | 0x80;  /* always non-zero */
    in.dev_cert_len = 64;
    memset(in.dev_cert, 0xDE, 64);
    in.ca_chain_len = 64;
    memset(in.ca_chain, 0xAD, 64);
    in.not_after = 1800000000;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_save(&in));
}

/* Assert the full dev_key region is zeroed in the backing store. */
static void assert_dev_key_region_is_zero(void)
{
    const uint8_t *p = cred_store_testhook_inspect_dev_key();
    for (size_t i = 0; i < CRED_DEV_KEY_MAX; i++) {
        if (p[i] != 0) {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "dev_key residue at offset %zu: 0x%02x", i, p[i]);
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

/* After a full clear(), load() is NOT_FOUND AND no key bytes remain. */
static void test_clear_full_scrubs_dev_key(void)
{
    seed_store_with_key_pattern();
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_clear());

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
    assert_dev_key_region_is_zero();
}

/* Power-fail after the marker-erase commit but before the scrub:
 * load() must return NOT_FOUND.  The dev_key bytes are still in place at
 * this stage -- this models the worst-case window the scrub closes.
 * Test the load() invariant: even with the key still on flash, the
 * caller's view says "not enrolled". */
static void test_clear_powerfail_after_marker_load_returns_not_found(void)
{
    seed_store_with_key_pattern();
    cred_store_testhook_clear_after_marker();

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* Power-fail after the scrub commit but before the final erase:
 * load() must return NOT_FOUND AND the dev_key region must already be
 * fully zero (no key DER fragments recoverable). */
static void test_clear_powerfail_after_scrub_no_residue(void)
{
    seed_store_with_key_pattern();
    cred_store_testhook_clear_after_scrub();

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
    assert_dev_key_region_is_zero();
}

/* Idempotent clear: a second clear() after a successful clear() is a no-op
 * and leaves dev_key zeroed. */
static void test_clear_double_no_residue(void)
{
    seed_store_with_key_pattern();
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_clear());
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_clear());

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
    assert_dev_key_region_is_zero();
}

/* save() followed by clear() leaves no residue (the integrated path). */
static void test_save_then_clear_no_residue(void)
{
    seed_store_with_key_pattern();
    /* Verify load() works first. */
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));

    /* Now clear and verify. */
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_clear());
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
    assert_dev_key_region_is_zero();
}

/* --------------------------------------------------------------------------
 * M3.B commit-boundary power-fail tests
 *
 * These tests exercise the two new testhooks that model the second commit
 * window in cred_store_save() (blobs committed, marker absent) and the
 * first commit window in cred_store_clear() (marker erased, blobs intact).
 *
 * The native backend is a SIMULATION: it models what load() observes at each
 * commit boundary, not physical flash page granularity.  See cred_store.h for
 * the full caveat.
 * -------------------------------------------------------------------------- */

/* Power-fail in clear() after marker erase but before scrub: load() returns
 * NOT_FOUND.  The raw key bytes are still in the backing store at this point
 * (worst-case forensic window), but the caller's view is "not enrolled". */
static void test_partial_clear_load_returns_not_found(void)
{
    seed_store_with_key_pattern();
    /* Verify the store is intact first */
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));

    /* Simulate power-fail after marker-erase commit, before scrub commit. */
    cred_store_testhook_partial_clear();
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* Power-fail in save() after blob commit (step 4) but before marker write
 * (step 5): load() must return NOT_FOUND. */
static void test_save_partial_blobs_no_marker_returns_not_found(void)
{
    cred_store_t in;
    memset(&in, 0, sizeof(in));
    in.dev_key_len  = 4;
    in.dev_key[0]   = 0xDE; in.dev_key[1] = 0xAD;
    in.dev_key[2]   = 0xBE; in.dev_key[3] = 0xEF;
    in.dev_cert_len = 1; in.dev_cert[0] = 0xCA;
    in.ca_chain_len = 1; in.ca_chain[0] = 0xFE;
    in.not_after    = 1800000000;

    /* Simulate: blobs committed (step 4) but power-fail before marker (step 5). */
    cred_store_testhook_save_partial_committed_blobs_no_marker(&in);

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
}

/* --------------------------------------------------------------------------
 * M3.D save-fail scrub tests
 *
 * Verify that when save() fails midway the scrub path zeroes the dev_key
 * region so no key DER fragments survive in the backing store.
 * -------------------------------------------------------------------------- */

/* After a simulated save-fail + scrub: load() returns NOT_FOUND AND the
 * dev_key region is fully zero. */
static void test_save_fail_with_scrub_no_residue(void)
{
    /* Pre-populate so the backing store has non-zero key bytes. */
    seed_store_with_key_pattern();
    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_OK, cred_store_load(&out));

    /* Simulate save_fail path: scrub executed, marker absent. */
    cred_store_testhook_save_fail_with_scrub();

    /* load() must say "not enrolled". */
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
    /* dev_key region must be zero -- no key DER fragments. */
    assert_dev_key_region_is_zero();
}

/* Starting from an empty store, simulated save-fail+scrub still leaves
 * dev_key all-zero (trivially; guards against uninitialised-memory issues). */
static void test_save_fail_with_scrub_on_empty_no_residue(void)
{
    /* setUp already cleared the store; dev_key is all-zero. */
    cred_store_testhook_save_fail_with_scrub();

    cred_store_t out;
    TEST_ASSERT_EQUAL_INT(ESP_ERR_NVS_NOT_FOUND, cred_store_load(&out));
    assert_dev_key_region_is_zero();
}

/* --------------------------------------------------------------------------
 * H3.B Concurrency test: two threads hammer save() + load() in parallel.
 *
 * Without the cred_store mutex, the in-memory backend's read of s_mem_store
 * could observe a torn copy mid-memcpy from a parallel save().  With the
 * mutex, every load() returns a fully-consistent snapshot -- either the
 * "A" snapshot or the "B" snapshot, never a mixture.
 *
 * The test runs both threads for a fixed number of iterations and verifies
 * that every successful load() yields a self-consistent record (the marker
 * byte at dev_key[0] matches the not_after field's identity).
 * -------------------------------------------------------------------------- */
#define CONCURRENT_ITERATIONS  2000

static cred_store_t s_thread_a_state;
static cred_store_t s_thread_b_state;
static _Atomic int  s_thread_stop = 0;
static _Atomic int  s_torn_reads  = 0;

static void *concurrent_saver(void *arg)
{
    const cred_store_t *src = (const cred_store_t *)arg;
    for (int i = 0; i < CONCURRENT_ITERATIONS; i++) {
        (void)cred_store_save(src);
    }
    return NULL;
}

static void *concurrent_loader(void *arg)
{
    (void)arg;
    cred_store_t out;
    while (!atomic_load(&s_thread_stop)) {
        if (cred_store_load(&out) == ESP_OK) {
            /* Identity check: if dev_key[0] is 0xAA the record must be the
             * "A" snapshot (not_after == 1000); if 0xBB it must be the "B"
             * snapshot (not_after == 2000).  Anything else is a torn read. */
            if (out.dev_key[0] == 0xAA && out.not_after != 1000) {
                atomic_fetch_add(&s_torn_reads, 1);
            } else if (out.dev_key[0] == 0xBB && out.not_after != 2000) {
                atomic_fetch_add(&s_torn_reads, 1);
            } else if (out.dev_key[0] != 0xAA && out.dev_key[0] != 0xBB) {
                atomic_fetch_add(&s_torn_reads, 1);
            }
        }
    }
    return NULL;
}

static void test_concurrent_save_load_no_tearing(void)
{
    memset(&s_thread_a_state, 0, sizeof(s_thread_a_state));
    s_thread_a_state.dev_key_len  = 64;
    memset(s_thread_a_state.dev_key, 0xAA, 64);
    s_thread_a_state.dev_cert_len = 1; s_thread_a_state.dev_cert[0] = 0xA1;
    s_thread_a_state.ca_chain_len = 1; s_thread_a_state.ca_chain[0] = 0xA2;
    s_thread_a_state.not_after = 1000;

    memset(&s_thread_b_state, 0, sizeof(s_thread_b_state));
    s_thread_b_state.dev_key_len  = 64;
    memset(s_thread_b_state.dev_key, 0xBB, 64);
    s_thread_b_state.dev_cert_len = 1; s_thread_b_state.dev_cert[0] = 0xB1;
    s_thread_b_state.ca_chain_len = 1; s_thread_b_state.ca_chain[0] = 0xB2;
    s_thread_b_state.not_after = 2000;

    atomic_store(&s_thread_stop, 0);
    atomic_store(&s_torn_reads, 0);

    pthread_t sa, sb, ld;
    pthread_create(&sa, NULL, concurrent_saver,  &s_thread_a_state);
    pthread_create(&sb, NULL, concurrent_saver,  &s_thread_b_state);
    pthread_create(&ld, NULL, concurrent_loader, NULL);

    pthread_join(sa, NULL);
    pthread_join(sb, NULL);
    atomic_store(&s_thread_stop, 1);
    pthread_join(ld, NULL);

    TEST_ASSERT_EQUAL_INT(0, atomic_load(&s_torn_reads));
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_not_after_correct_epoch);
    RUN_TEST(test_load_empty_returns_not_found);
    RUN_TEST(test_save_load_roundtrip);
    RUN_TEST(test_clear_after_save);
    RUN_TEST(test_parse_null_cert_returns_invalid_arg);
    RUN_TEST(test_parse_zero_len_returns_invalid_arg);
    RUN_TEST(test_parse_null_out_returns_invalid_arg);
    RUN_TEST(test_parse_corrupted_der_returns_fail);
    RUN_TEST(test_double_save_overwrites);
    RUN_TEST(test_save_null_returns_invalid_arg);
    RUN_TEST(test_load_null_returns_invalid_arg);
    RUN_TEST(test_clear_on_empty_is_idempotent);
    RUN_TEST(test_not_after_zero_is_preserved);
    /* parse_not_before tests */
    RUN_TEST(test_parse_not_before_correct_epoch);
    RUN_TEST(test_parse_not_before_null_cert_returns_invalid_arg);
    RUN_TEST(test_parse_not_before_zero_len_returns_invalid_arg);
    RUN_TEST(test_parse_not_before_null_out_returns_invalid_arg);
    RUN_TEST(test_parse_not_before_corrupted_der_returns_fail);
    RUN_TEST(test_parse_not_before_is_earlier_than_not_after);
    /* parse_x509_time routing */
    RUN_TEST(test_parse_x509_time_not_after_ne_not_before);
    /* Additional NVS round-trip and boundary tests */
    RUN_TEST(test_max_dev_key_preserves_all_bytes);
    RUN_TEST(test_max_dev_cert_preserves_all_bytes);
    RUN_TEST(test_min_ca_chain_one_byte_roundtrips);
    RUN_TEST(test_parse_not_after_one_byte_returns_fail);
    RUN_TEST(test_parse_not_after_garbage_returns_fail);
    RUN_TEST(test_multiple_clears_all_idempotent);
    RUN_TEST(test_not_after_uint64_max_preserved);
    /* B3 atomicity + schema version */
    RUN_TEST(test_atomicity_partial_write_returns_not_found);
    RUN_TEST(test_atomicity_full_save_loads_ok);
    RUN_TEST(test_schema_version_mismatch_returns_not_found);
    RUN_TEST(test_schema_version_zero_returns_not_found);
    /* L3.C schema_ver-absent (key never written by older firmware) */
    RUN_TEST(test_schema_absent_returns_not_found);
    /* C2.C scrub on clear / save-fail */
    RUN_TEST(test_clear_full_scrubs_dev_key);
    RUN_TEST(test_clear_powerfail_after_marker_load_returns_not_found);
    RUN_TEST(test_clear_powerfail_after_scrub_no_residue);
    RUN_TEST(test_clear_double_no_residue);
    RUN_TEST(test_save_then_clear_no_residue);
    /* M3.B commit-boundary power-fail */
    RUN_TEST(test_partial_clear_load_returns_not_found);
    RUN_TEST(test_save_partial_blobs_no_marker_returns_not_found);
    /* M3.D save-fail scrub */
    RUN_TEST(test_save_fail_with_scrub_no_residue);
    RUN_TEST(test_save_fail_with_scrub_on_empty_no_residue);
    /* H3.B concurrency */
    RUN_TEST(test_concurrent_save_load_no_tearing);
    return UNITY_END();
}
