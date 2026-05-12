/*
 * test_bridge_scrollback.c — integration tests for scrollback replay
 *
 * Simulates the SSH session flow:
 *   1. Push N lines of data into a scrollback buffer.
 *   2. Call scrollback_get_lines(sb, k, &len) to retrieve the last k lines.
 *   3. Verify the returned slice contains exactly k lines and ends with the
 *      expected content.
 *
 * Also exercises bridge_pump writing into a ring whose consumer drains into
 * a scrollback, confirming that the two components interoperate correctly.
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#include "unity.h"
#include "scrollback.h"
#include "bridge.h"
#include "ring.h"

void setUp(void)    {}
void tearDown(void) {}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static int count_newlines(const uint8_t *buf, size_t len)
{
    int n = 0;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n') n++;
    return n;
}

/* ── Test 1: push 50 lines, request last 20, verify count and tail ────────── */

void test_get_last_20_of_50_lines(void)
{
    const int TOTAL_LINES = 50;
    const int WANT_LINES  = 20;
    const size_t CAP = 16384;

    scrollback_t *sb = scrollback_create(CAP);
    TEST_ASSERT_NOT_NULL(sb);

    /* Push 50 numbered lines into the scrollback. */
    for (int i = 0; i < TOTAL_LINES; i++) {
        char line[64];
        int ln = snprintf(line, sizeof(line), "session line %04d\n", i);
        scrollback_push(sb, (const uint8_t *)line, (size_t)ln);
    }

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, WANT_LINES, &len);

    TEST_ASSERT_NOT_NULL(out);

    /* Must contain exactly WANT_LINES newlines */
    TEST_ASSERT_EQUAL_INT(WANT_LINES, count_newlines(out, len));

    /* First line in the result must be line 30 (0-indexed: lines 30-49) */
    const char *first_expected = "session line 0030\n";
    size_t fe_len = strlen(first_expected);
    TEST_ASSERT_GREATER_OR_EQUAL(fe_len, len);
    TEST_ASSERT_EQUAL_MEMORY(first_expected, out, fe_len);

    /* Last line in the result must be line 49 */
    const char *last_expected = "session line 0049\n";
    size_t le_len = strlen(last_expected);
    TEST_ASSERT_GREATER_OR_EQUAL(le_len, len);
    TEST_ASSERT_EQUAL_MEMORY(last_expected, out + len - le_len, le_len);

    free(out);
    free(sb);
}

/* ── Test 2: request more lines than stored — returns everything ──────────── */

void test_get_more_lines_than_stored_returns_all(void)
{
    scrollback_t *sb = scrollback_create(4096);
    TEST_ASSERT_NOT_NULL(sb);

    const int STORED = 5;
    for (int i = 0; i < STORED; i++) {
        char line[32];
        int ln = snprintf(line, sizeof(line), "ln%d\n", i);
        scrollback_push(sb, (const uint8_t *)line, (size_t)ln);
    }

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, 1000, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_INT(STORED, count_newlines(out, len));

    free(out);
    free(sb);
}

/* ── Test 3: scrollback after ring+bridge pump pipeline ─────────────────────
 *
 * Topology:
 *   producer → [src_ring] → bridge_pump → [dst_ring] → consumer → scrollback
 *
 * The bridge_pump runs in a background thread.  The consumer thread drains
 * dst_ring and pushes every byte into the scrollback.  After all data flows
 * through, we call scrollback_get_lines and verify the content.
 */

/* State shared between consumer thread and main */
typedef struct {
    ring_t        *src;
    scrollback_t  *sb;
    size_t         total_expected;
    int            result;  /* 0 = ok */
} consumer_arg_t;

static void *consumer_thread(void *arg)
{
    consumer_arg_t *a = (consumer_arg_t *)arg;
    uint8_t buf[256];
    size_t received = 0;

    while (received < a->total_expected) {
        int n = ring_recv(a->src, buf, sizeof(buf));
        if (n <= 0) { a->result = -1; return NULL; }
        scrollback_push(a->sb, buf, (size_t)n);
        received += (size_t)n;
    }
    a->result = 0;
    return NULL;
}

/* bridge_pump thread state */
typedef struct {
    ring_t        *src;
    ring_t        *dst;
    volatile bool  stop;
} pump_arg_t;

static int ring_read_cb(void *ctx, uint8_t *buf, size_t cap)
{
    return ring_recv((ring_t *)ctx, buf, cap);
}

static int ring_write_cb(void *ctx, const uint8_t *buf, size_t len)
{
    return ring_send((ring_t *)ctx, buf, len);
}

static void *pump_thread(void *arg)
{
    pump_arg_t *a = (pump_arg_t *)arg;
    bridge_pump(ring_read_cb, a->src, ring_write_cb, a->dst, &a->stop);
    return NULL;
}

void test_bridge_pump_into_scrollback(void)
{
    const int    LINE_COUNT = 30;
    const size_t RING_CAP   = 512;
    const size_t SB_CAP     = 16384;

    ring_t       *ab = ring_create(RING_CAP);
    ring_t       *ba = ring_create(RING_CAP);
    scrollback_t *sb = scrollback_create(SB_CAP);
    TEST_ASSERT_NOT_NULL(ab);
    TEST_ASSERT_NOT_NULL(ba);
    TEST_ASSERT_NOT_NULL(sb);

    /* Compute expected total bytes so consumer knows when to stop. */
    size_t total_bytes = 0;
    for (int i = 0; i < LINE_COUNT; i++) {
        char line[64];
        int ln = snprintf(line, sizeof(line), "pipe line %03d\n", i);
        total_bytes += (size_t)ln;
    }

    /* Start bridge_pump (ab → ba) */
    pump_arg_t parg = {.src = ab, .dst = ba, .stop = false};
    pthread_t pump_thr;
    pthread_create(&pump_thr, NULL, pump_thread, &parg);

    /* Start consumer (drains ba → scrollback) */
    consumer_arg_t carg = {.src = ba, .sb = sb,
                           .total_expected = total_bytes, .result = 99};
    pthread_t cons_thr;
    pthread_create(&cons_thr, NULL, consumer_thread, &carg);

    /* Producer: write lines into ab */
    for (int i = 0; i < LINE_COUNT; i++) {
        char line[64];
        int ln = snprintf(line, sizeof(line), "pipe line %03d\n", i);
        int sent = ring_send(ab, (const uint8_t *)line, (size_t)ln);
        TEST_ASSERT_EQUAL_INT(ln, sent);
    }

    /* Wait for consumer to finish */
    pthread_join(cons_thr, NULL);
    TEST_ASSERT_EQUAL_INT(0, carg.result);

    /* Shut down the pump */
    parg.stop = true;
    ring_close(ab);
    pthread_join(pump_thr, NULL);

    /* Verify scrollback content */
    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, LINE_COUNT, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_INT(LINE_COUNT, count_newlines(out, len));

    /* Last line must be "pipe line 029\n" */
    const char *last = "pipe line 029\n";
    size_t last_len = strlen(last);
    TEST_ASSERT_GREATER_OR_EQUAL(last_len, len);
    TEST_ASSERT_EQUAL_MEMORY(last, out + len - last_len, last_len);

    free(out);
    ring_free(ab);
    ring_free(ba);
    free(sb);
}

/* ── Test 4: push exactly 50 lines, request last 20, verify no off-by-one ── */

void test_ssh_session_replay_20_of_50(void)
{
    /* This is the canonical scenario described in the task spec. */
    const int TOTAL = 50;
    const int WANT  = 20;

    scrollback_t *sb = scrollback_create(65536);
    TEST_ASSERT_NOT_NULL(sb);

    for (int i = 0; i < TOTAL; i++) {
        char line[64];
        int ln = snprintf(line, sizeof(line), "term output line %d\n", i);
        scrollback_push(sb, (const uint8_t *)line, (size_t)ln);
    }

    size_t len = 0;
    uint8_t *out = scrollback_get_lines(sb, WANT, &len);

    TEST_ASSERT_NOT_NULL(out);
    TEST_ASSERT_EQUAL_INT(WANT, count_newlines(out, len));

    /* Verify first of the returned lines is line 30 */
    char expected_first[64];
    snprintf(expected_first, sizeof(expected_first), "term output line %d\n", TOTAL - WANT);
    size_t ef_len = strlen(expected_first);
    TEST_ASSERT_EQUAL_MEMORY(expected_first, out, ef_len);

    /* Verify last of the returned lines is line 49 */
    char expected_last[64];
    snprintf(expected_last, sizeof(expected_last), "term output line %d\n", TOTAL - 1);
    size_t el_len = strlen(expected_last);
    TEST_ASSERT_EQUAL_MEMORY(expected_last, out + len - el_len, el_len);

    free(out);
    free(sb);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_get_last_20_of_50_lines);
    RUN_TEST(test_get_more_lines_than_stored_returns_all);
    RUN_TEST(test_bridge_pump_into_scrollback);
    RUN_TEST(test_ssh_session_replay_20_of_50);
    return UNITY_END();
}
