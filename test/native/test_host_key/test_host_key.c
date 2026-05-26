/*
 * test_host_key.c -- Unit tests for format_fingerprint() from pubkey_auth.
 *
 * format_fingerprint() was extracted from host_key.c:log_fingerprint() so it
 * can be tested without wolfCrypt RNG, NVS, or wolfSSH.  The full
 * host_key.c flow (key generation + NVS persistence) is not testable natively
 * -- see test/README.md for the known-gaps list.
 */

#include <unity.h>
#include <string.h>
#include <stdint.h>
#include "pubkey_auth.h"

/* ------------------------------------------------------------------ */

void setUp(void) {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */

/* All-zeros digest -> "00:00:...:00" (32 bytes = 95 chars + NUL) */
static void test_all_zeros(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE] = {0};
    char out[PUBKEY_HASH_SIZE * 3];
    char *ret = format_fingerprint(digest, out, sizeof(out));
    TEST_ASSERT_NOT_NULL(ret);
    TEST_ASSERT_EQUAL_STRING(
        "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        ":00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        out);
}

/* All-0xff digest -> "ff:ff:...:ff" */
static void test_all_ff(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    memset(digest, 0xff, PUBKEY_HASH_SIZE);
    char out[PUBKEY_HASH_SIZE * 3];
    char *ret = format_fingerprint(digest, out, sizeof(out));
    TEST_ASSERT_NOT_NULL(ret);
    TEST_ASSERT_EQUAL_STRING(
        "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"
        ":ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
        out);
}

/* Specific known digest from QEMU boot log */
static void test_golden_value(void)
{
    /* First 8 bytes from the fingerprint seen in QEMU output:
     * 8b:2e:eb:84:0b:42:82:4e -- rest is run-specific, so only check prefix. */
    uint8_t digest[PUBKEY_HASH_SIZE] = {
        0x8b, 0x2e, 0xeb, 0x84, 0x0b, 0x42, 0x82, 0x4e,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    char out[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, out, sizeof(out));
    /* Verify the first 23 chars ("8b:2e:eb:84:0b:42:82:4e") */
    TEST_ASSERT_EQUAL_MEMORY("8b:2e:eb:84:0b:42:82:4e", out, 23);
}

/* No colons on the last byte -- string ends cleanly */
static void test_no_trailing_colon(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE] = {0};
    char out[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, out, sizeof(out));
    size_t len = strlen(out);
    TEST_ASSERT_NOT_EQUAL(':', out[len - 1]);
}

/* Buffer too small returns NULL */
static void test_small_buffer_returns_null(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE] = {0};
    char small[PUBKEY_HASH_SIZE * 3 - 1];
    char *ret = format_fingerprint(digest, small, sizeof(small));
    TEST_ASSERT_NULL(ret);
}

/* NULL digest returns NULL */
static void test_null_digest_returns_null(void)
{
    char out[PUBKEY_HASH_SIZE * 3];
    char *ret = format_fingerprint(NULL, out, sizeof(out));
    TEST_ASSERT_NULL(ret);
}

/* NULL out returns NULL */
static void test_null_out_returns_null(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE] = {0};
    char *ret = format_fingerprint(digest, NULL, 0);
    TEST_ASSERT_NULL(ret);
}

/* Output length is exactly PUBKEY_HASH_SIZE*3 - 1 (95 chars for 32 bytes) */
static void test_output_length(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE] = {0};
    char out[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(PUBKEY_HASH_SIZE * 3 - 1, (int)strlen(out));
}

/* Colons appear at every third position */
static void test_colon_positions(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE] = {0};
    char out[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, out, sizeof(out));
    for (int i = 0; i < PUBKEY_HASH_SIZE - 1; i++) {
        TEST_ASSERT_EQUAL_CHAR(':', out[i * 3 + 2]);
    }
}

/* Determinism: same digest -> identical output on two successive calls */
static void test_format_fingerprint_deterministic(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    for (int i = 0; i < PUBKEY_HASH_SIZE; i++) digest[i] = (uint8_t)(i * 7 + 3);

    char out1[PUBKEY_HASH_SIZE * 3];
    char out2[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, out1, sizeof(out1));
    format_fingerprint(digest, out2, sizeof(out2));
    TEST_ASSERT_EQUAL_STRING(out1, out2);
}

/* Key persistence simulation: re-formatting must reproduce same string */
static void test_format_fingerprint_reproduces_after_reinit(void)
{
    /* Simulates "persist hash, reload, re-format" round-trip */
    uint8_t original[PUBKEY_HASH_SIZE];
    memset(original, 0xA5, PUBKEY_HASH_SIZE);

    char first_format[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(original, first_format, sizeof(first_format));

    /* Copy the digest (as if stored to NVS and re-read) */
    uint8_t reloaded[PUBKEY_HASH_SIZE];
    memcpy(reloaded, original, PUBKEY_HASH_SIZE);

    char second_format[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(reloaded, second_format, sizeof(second_format));

    TEST_ASSERT_EQUAL_STRING(first_format, second_format);
}

/* Format validation: every byte-pair must be valid hex digits */
static void test_format_fingerprint_all_chars_are_hex(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    for (int i = 0; i < PUBKEY_HASH_SIZE; i++) digest[i] = (uint8_t)i;

    char out[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, out, sizeof(out));

    /* Inspect every byte: positions 0,1 of each triple must be hex; position 2 must be ':' or NUL */
    for (int i = 0; i < PUBKEY_HASH_SIZE; i++) {
        char hi = out[i * 3 + 0];
        char lo = out[i * 3 + 1];
        int hi_ok = (hi >= '0' && hi <= '9') || (hi >= 'a' && hi <= 'f');
        int lo_ok = (lo >= '0' && lo <= '9') || (lo >= 'a' && lo <= 'f');
        TEST_ASSERT_TRUE_MESSAGE(hi_ok, "high nibble not lowercase hex");
        TEST_ASSERT_TRUE_MESSAGE(lo_ok, "low nibble not lowercase hex");
    }
}

/* Length validation: output is exactly PUBKEY_HASH_SIZE*3 - 1 characters */
static void test_format_fingerprint_exact_byte_length(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    memset(digest, 0x42, PUBKEY_HASH_SIZE);

    char out[PUBKEY_HASH_SIZE * 3];
    char *ret = format_fingerprint(digest, out, sizeof(out));

    TEST_ASSERT_NOT_NULL(ret);
    /* Exactly 32*3 - 1 = 95 visible chars + NUL */
    TEST_ASSERT_EQUAL_INT(PUBKEY_HASH_SIZE * 3 - 1, (int)strlen(out));
}

/* A single changed digest byte changes the output string */
static void test_format_fingerprint_single_byte_change_differs(void)
{
    uint8_t d1[PUBKEY_HASH_SIZE], d2[PUBKEY_HASH_SIZE];
    memset(d1, 0x00, PUBKEY_HASH_SIZE);
    memset(d2, 0x00, PUBKEY_HASH_SIZE);
    d2[0] = 0x01;

    char s1[PUBKEY_HASH_SIZE * 3], s2[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(d1, s1, sizeof(s1));
    format_fingerprint(d2, s2, sizeof(s2));
    TEST_ASSERT_NOT_EQUAL(0, strcmp(s1, s2));
}

/* Minimum valid buffer size (exactly PUBKEY_HASH_SIZE*3) must succeed */
static void test_format_fingerprint_min_buffer_succeeds(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    memset(digest, 0x7E, PUBKEY_HASH_SIZE);

    char out[PUBKEY_HASH_SIZE * 3];   /* exactly min size */
    char *ret = format_fingerprint(digest, out, sizeof(out));
    TEST_ASSERT_NOT_NULL(ret);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_all_zeros);
    RUN_TEST(test_all_ff);
    RUN_TEST(test_golden_value);
    RUN_TEST(test_no_trailing_colon);
    RUN_TEST(test_small_buffer_returns_null);
    RUN_TEST(test_null_digest_returns_null);
    RUN_TEST(test_null_out_returns_null);
    RUN_TEST(test_output_length);
    RUN_TEST(test_colon_positions);
    /* New: determinism, reproducibility, validation */
    RUN_TEST(test_format_fingerprint_deterministic);
    RUN_TEST(test_format_fingerprint_reproduces_after_reinit);
    RUN_TEST(test_format_fingerprint_all_chars_are_hex);
    RUN_TEST(test_format_fingerprint_exact_byte_length);
    RUN_TEST(test_format_fingerprint_single_byte_change_differs);
    RUN_TEST(test_format_fingerprint_min_buffer_succeeds);
    return UNITY_END();
}
