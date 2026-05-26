/*
 * test_util.c -- native unit tests for lib/util helpers
 *
 * Covers:
 *   zeroize() -- volatile memory wipe
 */

#include "unity.h"
#include "zeroize.h"

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
    return UNITY_END();
}
