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
 * main
 * -------------------------------------------------------------------------- */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_zeroize_clears_buffer);
    RUN_TEST(test_zeroize_zero_len_is_noop);
    RUN_TEST(test_zeroize_single_byte);
    return UNITY_END();
}
