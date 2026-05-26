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

/* -- out_sz == 1: only room for NUL -> cannot fit any payload -------------- */

static void test_resize_out_sz_one_returns_zero(void)
{
    char buf[1] = {0x42};
    int n = term_resize_format(80, 24, buf, 1);
    TEST_ASSERT_EQUAL_INT(0, n);
}

/* -- out_sz == 0: trivially can't fit anything ----------------------------- */

static void test_resize_out_sz_zero_returns_zero(void)
{
    /* NULL-safe: out is non-NULL but out_sz == 0 should return 0. */
    char buf[8];
    int n = term_resize_format(80, 24, buf, 0);
    TEST_ASSERT_EQUAL_INT(0, n);
}

/* -- Only rows == 0 while cols is large: returns 0 ------------------------- */

static void test_resize_zero_rows_large_cols_returns_zero(void)
{
    char buf[32];
    int n = term_resize_format(999, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, n);
}

/* -- Asymmetric: cols > rows ----------------------------------------------- */

static void test_resize_wide_terminal(void)
{
    /* 220 cols x 50 rows -> "\033[8;50;220t" -- 11 bytes */
    char buf[32];
    int n = term_resize_format(220, 50, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(11, n);
    TEST_ASSERT_EQUAL_STRING("\033[8;50;220t", buf);
}

/* -- Format string content validation ------------------------------------- */

/* Output starts with ESC[ and ends with 't'. */
static void test_resize_format_prefix_suffix(void)
{
    char buf[32];
    term_resize_format(80, 24, buf, sizeof buf);
    TEST_ASSERT_EQUAL_CHAR(0x1B, buf[0]);
    TEST_ASSERT_EQUAL_CHAR('[',  buf[1]);
    TEST_ASSERT_EQUAL_CHAR('8',  buf[2]);
    TEST_ASSERT_EQUAL_CHAR(';',  buf[3]);
    /* Last character before NUL must be 't' */
    size_t len = strlen(buf);
    TEST_ASSERT_EQUAL_CHAR('t', buf[len - 1]);
}

/* rows comes before cols in the sequence: ESC[8;<rows>;<cols>t */
static void test_resize_row_col_order(void)
{
    char buf[32];
    /* Use distinct values so we can locate each in the string. */
    term_resize_format(132, 43, buf, sizeof buf);
    /* Expected: "\033[8;43;132t" */
    TEST_ASSERT_EQUAL_STRING("\033[8;43;132t", buf);
}

/* Buffer exactly one byte too small (payload+NUL does not fit). */
static void test_resize_buffer_one_short(void)
{
    /* 1x1 -> "\033[8;1;1t" is 8 bytes payload + 1 NUL = 9 total needed */
    char buf[9];  /* exactly fits */
    int n = term_resize_format(1, 1, buf, 9);
    TEST_ASSERT_EQUAL_INT(8, n);

    char buf8[8]; /* one short */
    int m = term_resize_format(1, 1, buf8, 8);
    TEST_ASSERT_EQUAL_INT(0, m);
}

/* cols=1, rows=UINT32_MAX -- asymmetric large value */
static void test_resize_tall_terminal(void)
{
    char buf[64];
    int n = term_resize_format(1, UINT32_MAX, buf, sizeof buf);
    /* "\033[8;4294967295;1t" = 17 chars */
    TEST_ASSERT_EQUAL_INT(17, n);
    TEST_ASSERT_EQUAL_STRING("\033[8;4294967295;1t", buf);
}

/* Return value matches strlen of output. */
static void test_resize_return_matches_strlen(void)
{
    char buf[64];
    int n = term_resize_format(200, 50, buf, sizeof buf);
    TEST_ASSERT_EQUAL_INT((int)strlen(buf), n);
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
    RUN_TEST(test_resize_out_sz_one_returns_zero);
    RUN_TEST(test_resize_out_sz_zero_returns_zero);
    RUN_TEST(test_resize_zero_rows_large_cols_returns_zero);
    RUN_TEST(test_resize_wide_terminal);
    /* Additional cases */
    RUN_TEST(test_resize_format_prefix_suffix);
    RUN_TEST(test_resize_row_col_order);
    RUN_TEST(test_resize_buffer_one_short);
    RUN_TEST(test_resize_tall_terminal);
    RUN_TEST(test_resize_return_matches_strlen);
    return UNITY_END();
}
