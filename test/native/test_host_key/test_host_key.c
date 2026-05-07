/*
 * test_host_key.c — Unit tests for format_fingerprint() from pubkey_auth.
 *
 * format_fingerprint() was extracted from host_key.c:log_fingerprint() so it
 * can be tested without wolfCrypt RNG, NVS, or wolfSSH.  The full
 * host_key.c flow (key generation + NVS persistence) is not testable natively
 * — see test/README.md for the known-gaps list.
 */

#include <unity.h>
#include <string.h>
#include <stdint.h>
#include "pubkey_auth.h"

/* ------------------------------------------------------------------ */

void setUp(void) {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */

/* All-zeros digest → "00:00:...:00" (32 bytes = 95 chars + NUL) */
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

/* All-0xff digest → "ff:ff:...:ff" */
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
     * 8b:2e:eb:84:0b:42:82:4e — rest is run-specific, so only check prefix. */
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

/* No colons on the last byte — string ends cleanly */
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
    return UNITY_END();
}
