/*
 * test_scrollback.c — unit tests for the scrollback circular buffer (native)
 *
 * Compiled with -DUNIT_TEST which activates the pthread-backed native
 * implementation in lib/scrollback/scrollback.c.
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "unity.h"
#include "scrollback.h"

void setUp(void)    {}
void tearDown(void) {}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Count newlines in a byte buffer. */
static int count_newlines(const uint8_t *buf, size_t len)
{
    int n = 0;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n') n++;
    return n;
}

/* ── Basic construction ──────────────────────────────────────────────────── */

void test_create_returns_non_null(void)
{
    scrollback_t *sb = scrollback_create(256);
    TEST_ASSERT_NOT_NULL(sb);
    free(sb);  /* direct free is not the API; but scrollback has no destroy —
                  we rely on process exit for tests; just confirm create works */
}

/* ── Empty buffer ────────────────────────────────────────────────────────── */

void test_empty_buffer_get_lines_returns_null(void)
{
    scrollback_t *sb = scrollback_create(256);
    TEST_ASSERT_NOT_NULL(sb);

    size_t len = 99;
    uint8_t *out = scrollback_get_lines(sb, 10, &len);

    TEST_ASSERT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(0, len);
    free(sb);
}

/* ── Push then get_lines ─────────────────────────────────────────────────── */

void test_push_then_get_lines_returns_content(void)
{
    scrollback_t *sb = scrollback_create(1024);
    TEST_ASSERT_NOT_NULL(sb);

    const char *msg = "hello\nworld\n";
    scrollback_push(sb, (const uint8_t *)msg, strlen(msg));

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 100, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(strlen(msg), len);
    TEST_ASSERT_EQUAL_MEMORY(msg, out, len);

    free(out);
    free(sb);
}

/* ── Wrap-around: push more than capacity, oldest data overwritten ────────── */

void test_overflow_wraps_oldest_data(void)
{
    /* Cap is 16 bytes.  Push 10 bytes of 'A', then 10 bytes of 'B'.
     * The buffer holds only 16, so the first 4 'A' bytes should be gone. */
    const size_t CAP = 16;
    scrollback_t *sb = scrollback_create(CAP);
    TEST_ASSERT_NOT_NULL(sb);

    uint8_t as[10], bs[10];
    memset(as, 'A', sizeof(as));
    memset(bs, 'B', sizeof(bs));

    scrollback_push(sb, as, 10);
    scrollback_push(sb, bs, 10);  /* total written = 20, but cap = 16 */

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 100, &len);

    /* Buffer should now contain exactly CAP bytes */
    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(CAP, len);

    /* Last 10 bytes must all be 'B' */
    for (size_t i = CAP - 10; i < CAP; i++)
        TEST_ASSERT_EQUAL_UINT8('B', out[i]);

    free(out);
    free(sb);
}

/* ── get_lines respects max_lines < total lines ───────────────────────────── */

void test_get_lines_returns_last_n_lines(void)
{
    scrollback_t *sb = scrollback_create(4096);
    TEST_ASSERT_NOT_NULL(sb);

    /* Push 10 lines */
    for (int i = 0; i < 10; i++) {
        char line[32];
        int ln = snprintf(line, sizeof(line), "line %d\n", i);
        scrollback_push(sb, (const uint8_t *)line, (size_t)ln);
    }

    /* Request only the last 3 lines */
    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 3, &len);

    TEST_ASSERT_NOT_NULL(out);
    /* The result should contain exactly 3 newlines */
    TEST_ASSERT_EQUAL_INT(3, count_newlines(out, len));

    /* The last three lines must end with "line 9\n" */
    const char *expected_suffix = "line 9\n";
    size_t sfx_len = strlen(expected_suffix);
    TEST_ASSERT_GREATER_OR_EQUAL(sfx_len, len);
    TEST_ASSERT_EQUAL_MEMORY(expected_suffix, out + len - sfx_len, sfx_len);

    free(out);
    free(sb);
}

/* ── max_lines > total lines returns everything ───────────────────────────── */

void test_get_lines_max_exceeds_total_returns_all(void)
{
    scrollback_t *sb = scrollback_create(4096);
    TEST_ASSERT_NOT_NULL(sb);

    const char *text = "alpha\nbeta\ngamma\n";
    scrollback_push(sb, (const uint8_t *)text, strlen(text));

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 1000, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(strlen(text), len);
    TEST_ASSERT_EQUAL_MEMORY(text, out, len);

    free(out);
    free(sb);
}

/* ── Data with no newlines: get_lines returns entire buffer ───────────────── */

void test_no_newlines_returns_entire_buffer(void)
{
    scrollback_t *sb = scrollback_create(256);
    TEST_ASSERT_NOT_NULL(sb);

    const char *data = "no newlines here at all";
    scrollback_push(sb, (const uint8_t *)data, strlen(data));

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 5, &len);

    TEST_ASSERT_NOT_NULL(out);
    /* No newlines → the entire buffer is treated as one partial line */
    TEST_ASSERT_EQUAL_size_t(strlen(data), len);
    TEST_ASSERT_EQUAL_MEMORY(data, out, len);

    free(out);
    free(sb);
}

/* ── Exact capacity boundary: push exactly cap bytes ─────────────────────── */

void test_exact_capacity_push(void)
{
    const size_t CAP = 32;
    scrollback_t *sb = scrollback_create(CAP);
    TEST_ASSERT_NOT_NULL(sb);

    uint8_t data[CAP];
    memset(data, 0x5A, CAP);
    scrollback_push(sb, data, CAP);

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 100, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(CAP, len);
    TEST_ASSERT_EQUAL_MEMORY(data, out, len);

    free(out);
    free(sb);
}

/* ── Wrap-around across circular boundary with line counting ──────────────── */

void test_wrap_and_get_lines_correct(void)
{
    /* Use a small cap to force wrap-around, then verify line retrieval. */
    const size_t CAP = 64;
    scrollback_t *sb = scrollback_create(CAP);
    TEST_ASSERT_NOT_NULL(sb);

    /* First, fill 50 bytes to advance head partway. */
    uint8_t filler[50];
    memset(filler, 'X', sizeof(filler));
    scrollback_push(sb, filler, sizeof(filler));

    /* Now push lines that will wrap across the end of the circular array. */
    const char *lines = "aaa\nbbb\nccc\n";
    scrollback_push(sb, (const uint8_t *)lines, strlen(lines));

    /* Ask for the last 3 lines */
    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 3, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_INT(3, count_newlines(out, len));

    /* The result must end with "ccc\n" */
    const char *tail = "ccc\n";
    TEST_ASSERT_GREATER_OR_EQUAL(strlen(tail), len);
    TEST_ASSERT_EQUAL_MEMORY(tail, out + len - strlen(tail), strlen(tail));

    free(out);
    free(sb);
}

/* ── get_lines with max_lines == 0 returns nothing (empty frame) ─────────── */

void test_get_lines_zero_max_returns_null_or_empty(void)
{
    scrollback_t *sb = scrollback_create(256);
    TEST_ASSERT_NOT_NULL(sb);

    const char *text = "line1\nline2\n";
    scrollback_push(sb, (const uint8_t *)text, strlen(text));

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 0, &len);

    /* Requesting 0 lines: implementation may return NULL or 0-length result. */
    if (out != NULL) {
        TEST_ASSERT_EQUAL_size_t(0, len);
        free(out);
    } else {
        TEST_ASSERT_EQUAL_size_t(0, len);
    }
    free(sb);
}

/* ── Multiple pushes accumulate correctly ─────────────────────────────────── */

void test_multiple_pushes_accumulate(void)
{
    scrollback_t *sb = scrollback_create(4096);
    TEST_ASSERT_NOT_NULL(sb);

    scrollback_push(sb, (const uint8_t *)"foo\n", 4);
    scrollback_push(sb, (const uint8_t *)"bar\n", 4);
    scrollback_push(sb, (const uint8_t *)"baz\n", 4);

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 100, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_size_t(12, len);  /* "foo\nbar\nbaz\n" */
    TEST_ASSERT_EQUAL_MEMORY("foo\nbar\nbaz\n", out, 12);

    free(out);
    free(sb);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_returns_non_null);
    RUN_TEST(test_empty_buffer_get_lines_returns_null);
    RUN_TEST(test_push_then_get_lines_returns_content);
    RUN_TEST(test_overflow_wraps_oldest_data);
    RUN_TEST(test_get_lines_returns_last_n_lines);
    RUN_TEST(test_get_lines_max_exceeds_total_returns_all);
    RUN_TEST(test_no_newlines_returns_entire_buffer);
    RUN_TEST(test_exact_capacity_push);
    RUN_TEST(test_wrap_and_get_lines_correct);
    RUN_TEST(test_get_lines_zero_max_returns_null_or_empty);
    RUN_TEST(test_multiple_pushes_accumulate);
    return UNITY_END();
}
