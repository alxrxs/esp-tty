/*
 * test_util.c -- native unit tests for lib/util helpers
 *
 * Covers:
 *   zeroize() -- volatile memory wipe
 */

#include "unity.h"
#include "zeroize.h"
#include "log_sanitize.h"

#include <stdint.h>
#include <string.h>

void setUp(void)    {}
void tearDown(void) {}

/* --------------------------------------------------------------------------
 * zeroize: filled buffer is cleared to all-zero bytes
 * -------------------------------------------------------------------------- */
static void test_zeroize_clears_buffer(void)
{
    uint8_t buf[64];
    memset(buf, 0xAB, sizeof(buf));

    zeroize(buf, sizeof(buf));

    for (size_t i = 0; i < sizeof(buf); i++) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, buf[i], "expected zero after zeroize");
    }
}

/* --------------------------------------------------------------------------
 * zeroize: zero-length call is a no-op (must not crash or modify anything)
 * -------------------------------------------------------------------------- */
static void test_zeroize_zero_len_is_noop(void)
{
    uint8_t buf[8];
    memset(buf, 0xCD, sizeof(buf));

    zeroize(buf, 0);

    for (size_t i = 0; i < sizeof(buf); i++) {
        TEST_ASSERT_EQUAL_HEX8(0xCD, buf[i]);
    }
}

/* --------------------------------------------------------------------------
 * zeroize: single-byte buffer
 * -------------------------------------------------------------------------- */
static void test_zeroize_single_byte(void)
{
    uint8_t b = 0xFF;
    zeroize(&b, 1);
    TEST_ASSERT_EQUAL_HEX8(0x00, b);
}

/* --------------------------------------------------------------------------
 * zeroize: large buffer (1 KiB) is fully cleared
 * -------------------------------------------------------------------------- */
static void test_zeroize_large_buffer(void)
{
    static uint8_t buf[1024]; /* static so it survives without stack-size worries */
    memset(buf, 0xFF, sizeof(buf));
    zeroize(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) {
        TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, buf[i], "large buffer not zeroed");
    }
}

/* --------------------------------------------------------------------------
 * zeroize: partial region -- bytes outside the range must be untouched
 * -------------------------------------------------------------------------- */
static void test_zeroize_partial_range(void)
{
    uint8_t buf[16];
    memset(buf, 0xBB, sizeof(buf));

    /* Zero only the middle 8 bytes (offset 4..11). */
    zeroize(buf + 4, 8);

    /* First 4 bytes must be 0xBB. */
    for (int i = 0; i < 4; i++)
        TEST_ASSERT_EQUAL_HEX8(0xBB, buf[i]);
    /* Middle 8 must be 0x00. */
    for (int i = 4; i < 12; i++)
        TEST_ASSERT_EQUAL_HEX8(0x00, buf[i]);
    /* Last 4 must be 0xBB. */
    for (int i = 12; i < 16; i++)
        TEST_ASSERT_EQUAL_HEX8(0xBB, buf[i]);
}

/* --------------------------------------------------------------------------
 * zeroize: returns void (no crash) on aligned 4-byte buffer
 * -------------------------------------------------------------------------- */
static void test_zeroize_four_bytes(void)
{
    uint32_t val = 0xDEADBEEF;
    zeroize(&val, sizeof(val));
    TEST_ASSERT_EQUAL_UINT32(0x00000000u, val);
}

/* --------------------------------------------------------------------------
 * zeroize: calling repeatedly on same memory is safe
 * -------------------------------------------------------------------------- */
static void test_zeroize_idempotent(void)
{
    uint8_t buf[8];
    memset(buf, 0xAA, sizeof(buf));
    zeroize(buf, sizeof(buf));
    zeroize(buf, sizeof(buf)); /* second call on already-zeroed memory */
    for (size_t i = 0; i < sizeof(buf); i++)
        TEST_ASSERT_EQUAL_HEX8(0x00, buf[i]);
}

/* --------------------------------------------------------------------------
 * log_sanitize: plain printable ASCII passes through untouched
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_plain_ascii(void)
{
    char out[64];
    const char *in = "hello-world_42";
    size_t n = log_sanitize(out, sizeof(out), in, strlen(in));
    TEST_ASSERT_EQUAL_STRING("hello-world_42", out);
    TEST_ASSERT_EQUAL_size_t(strlen(in), n);
}

/* --------------------------------------------------------------------------
 * log_sanitize: newline, carriage return, tab escaped
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_control_bytes(void)
{
    char out[64];
    const char in[] = "ab\ncd\rEF\t";
    log_sanitize(out, sizeof(out), in, sizeof(in) - 1);
    TEST_ASSERT_EQUAL_STRING("ab\\x0acd\\x0dEF\\x09", out);
}

/* --------------------------------------------------------------------------
 * log_sanitize: ANSI ESC clear-screen is escaped
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_ansi_escape(void)
{
    char out[64];
    const char in[] = "\x1b[2Jfoo";
    log_sanitize(out, sizeof(out), in, sizeof(in) - 1);
    TEST_ASSERT_EQUAL_STRING("\\x1b[2Jfoo", out);
}

/* --------------------------------------------------------------------------
 * log_sanitize: embedded NUL byte is escaped (and processing continues
 *               past it -- we do NOT use strlen())
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_embedded_nul(void)
{
    char out[64];
    const uint8_t in[] = { 'a', 'b', 0x00, 'c', 'd' };
    log_sanitize(out, sizeof(out), in, sizeof(in));
    TEST_ASSERT_EQUAL_STRING("ab\\x00cd", out);
}

/* --------------------------------------------------------------------------
 * log_sanitize: quotes and backslash are escaped to avoid confusing parsers
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_quotes_and_backslash(void)
{
    char out[64];
    const char in[] = "a\"b'c\\d";
    log_sanitize(out, sizeof(out), in, sizeof(in) - 1);
    TEST_ASSERT_EQUAL_STRING("a\\x22b\\x27c\\x5cd", out);
}

/* --------------------------------------------------------------------------
 * log_sanitize: high bytes (0x80..0xff) escaped
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_high_bytes(void)
{
    char out[64];
    const uint8_t in[] = { 0x80, 0xff, 'X', 0xaa };
    log_sanitize(out, sizeof(out), in, sizeof(in));
    TEST_ASSERT_EQUAL_STRING("\\x80\\xffX\\xaa", out);
}

/* --------------------------------------------------------------------------
 * log_sanitize: output is NUL-terminated even when buffer too small
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_truncation_nul_terminated(void)
{
    char out[5]; /* room for 4 chars + NUL */
    const char *in = "abcdefghij";
    log_sanitize(out, sizeof(out), in, strlen(in));
    TEST_ASSERT_EQUAL_size_t(0, out[4]); /* NUL */
    /* Output should be the first 4 chars */
    TEST_ASSERT_EQUAL_STRING("abcd", out);
}

/* --------------------------------------------------------------------------
 * log_sanitize: out_cap == 0 is a safe no-op
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_zero_cap(void)
{
    char out[4] = { 'X', 'Y', 'Z', '\0' };
    size_t n = log_sanitize(out, 0, "abc", 3);
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_EQUAL_CHAR('X', out[0]); /* untouched */
}

/* --------------------------------------------------------------------------
 * log_sanitize: NULL input + nonzero len is treated as empty
 * -------------------------------------------------------------------------- */
static void test_log_sanitize_null_input(void)
{
    char out[16];
    out[0] = 'X';
    size_t n = log_sanitize(out, sizeof(out), NULL, 5);
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_EQUAL_CHAR('\0', out[0]);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_zeroize_clears_buffer);
    RUN_TEST(test_zeroize_zero_len_is_noop);
    RUN_TEST(test_zeroize_single_byte);
    /* Additional cases */
    RUN_TEST(test_zeroize_large_buffer);
    RUN_TEST(test_zeroize_partial_range);
    RUN_TEST(test_zeroize_four_bytes);
    RUN_TEST(test_zeroize_idempotent);
    /* log_sanitize */
    RUN_TEST(test_log_sanitize_plain_ascii);
    RUN_TEST(test_log_sanitize_control_bytes);
    RUN_TEST(test_log_sanitize_ansi_escape);
    RUN_TEST(test_log_sanitize_embedded_nul);
    RUN_TEST(test_log_sanitize_quotes_and_backslash);
    RUN_TEST(test_log_sanitize_high_bytes);
    RUN_TEST(test_log_sanitize_truncation_nul_terminated);
    RUN_TEST(test_log_sanitize_zero_cap);
    RUN_TEST(test_log_sanitize_null_input);
    return UNITY_END();
}
