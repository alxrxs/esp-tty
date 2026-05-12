/*
 * test_term_resize.c -- unit tests for term_resize_format (native)
 *
 * Verifies the xterm "set window size" CSI formatter -- exact byte output,
 * return values, and all early-return / failure modes (zero dims, NULL out,
 * undersized buffer).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "unity.h"
#include "term_resize.h"

void setUp(void)    {}
void tearDown(void) {}

/* -- Happy-path cases ------------------------------------------------------ */

static void test_resize_typical_80x24(void)
{
    char buf[32];
    int n = term_resize_format(80, 24, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(10, n);
    TEST_ASSERT_EQUAL_STRING("\033[8;24;80t", buf);
}

static void test_resize_one_by_one(void)
{
    char buf[32];
    int n = term_resize_format(1, 1, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(8, n);
    TEST_ASSERT_EQUAL_STRING("\033[8;1;1t", buf);
}

static void test_resize_large(void)
{
    char buf[32];
    int n = term_resize_format(500, 200, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(12, n);
    TEST_ASSERT_EQUAL_STRING("\033[8;200;500t", buf);
}

/* -- Zero-dimension early returns ------------------------------------------- */

static void test_resize_zero_cols_returns_zero(void)
{
    char buf[32];
    int n = term_resize_format(0, 24, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(0, n);
}

static void test_resize_zero_rows_returns_zero(void)
{
    char buf[32];
    int n = term_resize_format(80, 0, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(0, n);
}

static void test_resize_both_zero_returns_zero(void)
{
    char buf[32];
    int n = term_resize_format(0, 0, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(0, n);
}

/* -- Defensive NULL / undersized buffer ------------------------------------- */

static void test_resize_null_out_returns_zero(void)
{
    int n = term_resize_format(80, 24, NULL, 32);
    TEST_ASSERT_EQUAL_INT(0, n);
}

static void test_resize_buffer_too_small(void)
{
    char buf[4];
    int n = term_resize_format(80, 24, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(0, n);
}

/* -- Exact-fit boundary: 10 bytes of payload + 1 NUL = 11 ----------------- */

static void test_resize_buffer_exact_fit(void)
{
    /* 80x24 -> "\033[8;24;80t" -- exactly 10 bytes of payload. */
    char buf11[11];
    int n11 = term_resize_format(80, 24, buf11, sizeof buf11);
    TEST_ASSERT_EQUAL_INT(10, n11);
    TEST_ASSERT_EQUAL_STRING("\033[8;24;80t", buf11);

    /* Same payload, but no room for NUL -> must return 0. */
    char buf10[10];
    int n10 = term_resize_format(80, 24, buf10, sizeof buf10);
    TEST_ASSERT_EQUAL_INT(0, n10);
}

/* -- Largest 32-bit values ------------------------------------------------ */

static void test_resize_max_word32(void)
{
    /* "\033[8;4294967295;4294967295t" -- 26 bytes payload + NUL -> buf 64 is safe. */
    char buf[64];
    int n = term_resize_format(UINT32_MAX, UINT32_MAX, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT(26, n);
    TEST_ASSERT_EQUAL_STRING("\033[8;4294967295;4294967295t", buf);
}

/* -- Main ----------------------------------------------------------------- */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_resize_typical_80x24);
    RUN_TEST(test_resize_one_by_one);
    RUN_TEST(test_resize_large);
    RUN_TEST(test_resize_zero_cols_returns_zero);
    RUN_TEST(test_resize_zero_rows_returns_zero);
    RUN_TEST(test_resize_both_zero_returns_zero);
    RUN_TEST(test_resize_null_out_returns_zero);
    RUN_TEST(test_resize_buffer_too_small);
    RUN_TEST(test_resize_buffer_exact_fit);
    RUN_TEST(test_resize_max_word32);
    return UNITY_END();
}
