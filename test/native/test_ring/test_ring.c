/*
 * test_ring.c -- unit tests for ring buffer (native, RING_NATIVE=1)
 *
 * Tests: FIFO correctness, blocking semantics, wrap-around, close.
 * Compiled with -DRING_NATIVE=1 by the PlatformIO native environment.
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "unity.h"
#include "ring.h"

/* ------------------------------------------------------------------ */
void setUp(void)    {}
void tearDown(void) {}
/* ------------------------------------------------------------------ */

/*
 * Rendezvous helper -- eliminates the fragile usleep(20000) races on the
 * three "close unblocks a blocked thread" tests.
 *
 * Usage pattern:
 *   Main thread:  rendezvous_init(&rv);
 *   Worker thread: rendezvous_signal(&rv);  // BEFORE calling the blocking op
 *                  <call blocking ring op>
 *   Main thread:  rendezvous_wait(&rv);     // waits until worker is just about
 *                                           // to block; then acts on the ring
 *
 * A 1 ms sleep after rendezvous_wait() gives the OS time to actually schedule
 * the worker into the blocking syscall, shrinking the race window to ~1 ms
 * (vs. 20 ms with the original plain usleep).
 */
typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             fired;
} rendezvous_t;

static void rendezvous_init(rendezvous_t *rv)
{
    pthread_mutex_init(&rv->mu, NULL);
    pthread_cond_init(&rv->cv, NULL);
    rv->fired = 0;
}

static void rendezvous_signal(rendezvous_t *rv)
{
    pthread_mutex_lock(&rv->mu);
    rv->fired = 1;
    pthread_cond_signal(&rv->cv);
    pthread_mutex_unlock(&rv->mu);
}

static void rendezvous_wait(rendezvous_t *rv)
{
    pthread_mutex_lock(&rv->mu);
    while (!rv->fired)
        pthread_cond_wait(&rv->cv, &rv->mu);
    pthread_mutex_unlock(&rv->mu);
    /* Yield briefly so the OS actually schedules the worker into the blocking
     * call before we act on the ring. */
    usleep(1000);
}

static void rendezvous_destroy(rendezvous_t *rv)
{
    pthread_cond_destroy(&rv->cv);
    pthread_mutex_destroy(&rv->mu);
}

/* --- ring_create edge cases --------------------------------------- */

void test_ring_create_min_capacity(void)
{
    /* capacity=1 is the smallest useful ring */
    ring_t *r = ring_create(1);
    TEST_ASSERT_NOT_NULL(r);
    uint8_t b = 0x42;
    TEST_ASSERT_EQUAL_INT(1, ring_try_send(r, &b, 1));
    /* Now full -- another try_send should return 0 */
    uint8_t extra = 0xFF;
    TEST_ASSERT_EQUAL_INT(0, ring_try_send(r, &extra, 1));
    ring_free(r);
}

void test_ring_free_null_is_safe(void)
{
    /* ring_free(NULL) must not crash */
    ring_free(NULL);
    TEST_PASS();
}

/* --- Basic FIFO correctness ---------------------------------------- */

void test_ring_fifo_order(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    uint8_t tx[] = {1, 2, 3, 4, 5};
    TEST_ASSERT_EQUAL_INT((int)sizeof(tx),
                          ring_send(r, tx, sizeof(tx)));

    uint8_t rx[sizeof(tx)] = {0};
    int got = 0;
    while ((size_t)got < sizeof(rx)) {
        int n = ring_recv(r, rx + got, sizeof(rx) - (size_t)got);
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        got += n;
    }

    TEST_ASSERT_EQUAL_MEMORY(tx, rx, sizeof(tx));
    ring_free(r);
}

/* --- Wrap-around: write past end of circular buffer ---------------- */

void test_ring_wrap(void)
{
    const size_t CAP = 8;
    ring_t *r = ring_create(CAP);
    TEST_ASSERT_NOT_NULL(r);

    /* Fill buffer, drain half, fill again -- forces wrap-around */
    uint8_t ones[8];
    memset(ones, 1, sizeof(ones));
    TEST_ASSERT_EQUAL_INT(8, ring_send(r, ones, 8));

    uint8_t tmp[4];
    int drained = 0;
    while (drained < 4) {
        int n = ring_recv(r, tmp + drained, (size_t)(4 - drained));
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        drained += n;
    }

    uint8_t twos[4];
    memset(twos, 2, sizeof(twos));
    TEST_ASSERT_EQUAL_INT(4, ring_send(r, twos, 4));

    /* Drain the remaining 8 bytes: 4 ones + 4 twos */
    uint8_t out[8] = {0};
    int total = 0;
    while (total < 8) {
        int n = ring_recv(r, out + total, (size_t)(8 - total));
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        total += n;
    }
    TEST_ASSERT_EACH_EQUAL_UINT8(1, out,     4);
    TEST_ASSERT_EACH_EQUAL_UINT8(2, out + 4, 4);

    ring_free(r);
}

/* --- Close unblocks a blocked receiver ----------------------------- */

typedef struct { ring_t *r; int result; rendezvous_t *rv; } recv_arg_t;

static void *blocked_recv_thread(void *arg)
{
    recv_arg_t *a = arg;
    uint8_t buf[4];
    /* Signal the main thread that we are about to block, then block. */
    rendezvous_signal(a->rv);
    a->result = ring_recv(a->r, buf, sizeof(buf));
    return NULL;
}

void test_ring_close_unblocks_recv(void)
{
    ring_t *r = ring_create(16);
    TEST_ASSERT_NOT_NULL(r);

    rendezvous_t rv;
    rendezvous_init(&rv);

    recv_arg_t arg = {.r = r, .result = 0, .rv = &rv};
    pthread_t thr;
    pthread_create(&thr, NULL, blocked_recv_thread, &arg);

    rendezvous_wait(&rv); /* wait until worker is about to block, then proceed */
    ring_close(r);

    pthread_join(thr, NULL);
    rendezvous_destroy(&rv);
    TEST_ASSERT_EQUAL_INT(-1, arg.result);
    ring_free(r);
}

/* --- Blocking send: producer blocks when full, drains as consumer reads */

typedef struct {
    ring_t  *r;
    size_t   total;   /* bytes to send */
    int      result;  /* 0 = ok, -1 = error */
} producer_arg_t;

static void *producer_thread(void *arg)
{
    producer_arg_t *a = arg;
    uint8_t byte = 0xAB;
    for (size_t i = 0; i < a->total; i++) {
        if (ring_send(a->r, &byte, 1) < 0) {
            a->result = -1;
            return NULL;
        }
    }
    a->result = 0;
    return NULL;
}

void test_ring_backpressure_lossless(void)
{
    const size_t N = 4096;
    ring_t *r = ring_create(64); /* tiny ring, large data */
    TEST_ASSERT_NOT_NULL(r);

    producer_arg_t pa = {.r = r, .total = N, .result = 99};
    pthread_t thr;
    pthread_create(&thr, NULL, producer_thread, &pa);

    uint8_t buf[16];
    size_t received = 0;
    while (received < N) {
        int n = ring_recv(r, buf, sizeof(buf));
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        received += (size_t)n;
    }

    pthread_join(thr, NULL);
    TEST_ASSERT_EQUAL_INT(0, pa.result);
    TEST_ASSERT_EQUAL_size_t(N, received);
    ring_free(r);
}

/* --- Send on a closed ring returns -1 ------------------------------ */

void test_ring_send_on_closed_ring_returns_error(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    ring_close(r);

    int ret = ring_send(r, "hello", 5);
    TEST_ASSERT_EQUAL_INT(-1, ret);

    ring_free(r);
}

/* --- Recv drains buffered data before returning EOF (pthread contract) --
 *
 * This test verifies the pthread/native backend's drain-before-EOF contract:
 * after ring_close(), ring_recv() must first return any data that was already
 * in the buffer, and only return -1 (EOF) on the NEXT call when the buffer is
 * truly empty.
 *
 * NOTE: The FreeRTOS backend in lib/ring/ring.c returns -1 immediately on
 * ring_close(), dropping any in-flight buffered data. This divergence is
 * intentional and is NOT fixed here because ring_close() is only called during
 * single-session SSH teardown (bridge_pump -> ring_close -> pump tasks exit),
 * at which point buffered data is already destined to be discarded.  Testing
 * the FreeRTOS side would require target hardware and would require modifying
 * the FreeRTOS backend -- both are out of scope per the project hard constraints.
 */
void test_ring_recv_drains_buffered_then_returns_eof(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    /* Send 10 bytes, then immediately close the ring */
    uint8_t payload[10];
    memset(payload, 0xAB, sizeof(payload));
    int sent = ring_send(r, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT((int)sizeof(payload), sent);

    ring_close(r);

    /* First recv: must return the buffered 10 bytes (not -1) */
    uint8_t buf[64];
    int got = ring_recv(r, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT((int)sizeof(payload), got);
    TEST_ASSERT_EQUAL_MEMORY(payload, buf, sizeof(payload));

    /* Second recv: buffer is empty and ring is closed -> EOF */
    int eof = ring_recv(r, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-1, eof);

    ring_free(r);
}

/* -- ring_try_send tests --------------------------------------------------- */

/* try_send into an empty ring writes all bytes */
void test_ring_try_send_when_empty(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    uint8_t tx[] = {0xAA, 0xBB, 0xCC, 0xDD};
    int written = ring_try_send(r, tx, sizeof(tx));
    TEST_ASSERT_EQUAL_INT((int)sizeof(tx), written);

    /* Read back and verify */
    uint8_t rx[sizeof(tx)] = {0};
    int got = 0;
    while ((size_t)got < sizeof(rx)) {
        int n = ring_recv(r, rx + got, sizeof(rx) - (size_t)got);
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        got += n;
    }
    TEST_ASSERT_EQUAL_MEMORY(tx, rx, sizeof(tx));

    ring_free(r);
}

/* try_send into a full ring returns 0 -- does not block */
void test_ring_try_send_when_full(void)
{
    const size_t CAP = 8;
    ring_t *r = ring_create(CAP);
    TEST_ASSERT_NOT_NULL(r);

    /* Fill the ring completely via blocking send */
    uint8_t fill[8];
    memset(fill, 0x55, sizeof(fill));
    TEST_ASSERT_EQUAL_INT(8, ring_send(r, fill, 8));

    /* Now try_send must return 0 immediately (ring is full) */
    uint8_t extra[] = {0xFF};
    int written = ring_try_send(r, extra, sizeof(extra));
    TEST_ASSERT_EQUAL_INT(0, written);

    ring_free(r);
}

/* try_send writes what fits when ring is almost full */
void test_ring_try_send_partial_when_almost_full(void)
{
    const size_t CAP = 8;
    ring_t *r = ring_create(CAP);
    TEST_ASSERT_NOT_NULL(r);

    /* Fill 6 of 8 bytes */
    uint8_t fill[6];
    memset(fill, 0x11, sizeof(fill));
    TEST_ASSERT_EQUAL_INT(6, ring_send(r, fill, 6));

    /* try_send 4 bytes; only 2 slots remain -> should write exactly 2 */
    uint8_t data[4] = {0x22, 0x22, 0x22, 0x22};
    int written = ring_try_send(r, data, sizeof(data));
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, written);
    TEST_ASSERT_LESS_OR_EQUAL_INT(2, written);  /* at most 2 fit */
    /* The ring must be full or near-full -- reading must return something */
    uint8_t out[8];
    int got = ring_recv(r, out, sizeof(out));
    TEST_ASSERT_GREATER_THAN_INT(0, got);

    ring_free(r);
}

/* try_send on a closed ring returns -1 */
void test_ring_try_send_on_closed_ring(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    ring_close(r);

    uint8_t buf[] = {0xDE, 0xAD};
    int result = ring_try_send(r, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-1, result);

    ring_free(r);
}

/* -- ring_reopen tests ----------------------------------------------------- */

/* reopen clears the closed flag so send/recv work again */
void test_ring_reopen_clears_closed_flag(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    ring_close(r);

    uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};
    TEST_ASSERT_EQUAL_INT(-1, ring_send(r, hello, sizeof(hello)));

    ring_reopen(r);

    TEST_ASSERT_EQUAL_INT(5, ring_send(r, hello, sizeof(hello)));

    ring_free(r);
}

/* reopen drains any stale data from the previous session */
void test_ring_reopen_drains_stale_data(void)
{
    ring_t *r = ring_create(32);
    TEST_ASSERT_NOT_NULL(r);

    uint8_t aaaa[8];
    memset(aaaa, 'A', sizeof(aaaa));
    TEST_ASSERT_EQUAL_INT(8, ring_send(r, aaaa, sizeof(aaaa)));

    ring_close(r);
    ring_reopen(r);

    uint8_t bbbb[4];
    memset(bbbb, 'B', sizeof(bbbb));
    TEST_ASSERT_EQUAL_INT(4, ring_send(r, bbbb, sizeof(bbbb)));

    uint8_t rx[16] = {0};
    int got = ring_recv(r, rx, sizeof(rx));
    TEST_ASSERT_EQUAL_INT(4, got);
    TEST_ASSERT_EACH_EQUAL_UINT8('B', rx, 4);

    ring_free(r);
}

/* reopen on a NULL ring must not crash */
void test_ring_reopen_on_null_is_noop(void)
{
    ring_reopen(NULL);
    TEST_PASS();
}

/* reopen on an already-open ring is a safe idempotent operation */
void test_ring_reopen_on_open_ring_is_idempotent(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    ring_reopen(r);

    uint8_t tx[] = {0x10, 0x20, 0x30, 0x40};
    TEST_ASSERT_EQUAL_INT(4, ring_send(r, tx, sizeof(tx)));

    uint8_t rx[sizeof(tx)] = {0};
    int got = 0;
    while ((size_t)got < sizeof(rx)) {
        int n = ring_recv(r, rx + got, sizeof(rx) - (size_t)got);
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        got += n;
    }
    TEST_ASSERT_EQUAL_MEMORY(tx, rx, sizeof(tx));

    ring_free(r);
}

/* After close + reopen, a fresh recv must block for new data (no stale -1) */
void test_ring_reopen_then_recv_blocks_for_new_data(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    ring_close(r);
    ring_reopen(r);

    rendezvous_t rv;
    rendezvous_init(&rv);

    recv_arg_t arg = {.r = r, .result = 0, .rv = &rv};
    pthread_t thr;
    pthread_create(&thr, NULL, blocked_recv_thread, &arg);

    rendezvous_wait(&rv); /* wait until thread is about to block */

    uint8_t tx[] = {'x', 'y', 'z'};
    TEST_ASSERT_EQUAL_INT(3, ring_send(r, tx, sizeof(tx)));

    pthread_join(thr, NULL);
    rendezvous_destroy(&rv);
    TEST_ASSERT_EQUAL_INT(3, arg.result);

    ring_free(r);
}

/* -- extra ring_try_send tests --------------------------------------------- */

/* try_send returns EXACTLY the remaining space when partial-filled */
void test_ring_try_send_partial_writes_exactly_remaining_space(void)
{
    const size_t CAP = 8;
    ring_t *r = ring_create(CAP);
    TEST_ASSERT_NOT_NULL(r);

    /* Fill 6 of 8 bytes */
    uint8_t fill[6];
    memset(fill, 0x11, sizeof(fill));
    TEST_ASSERT_EQUAL_INT(6, ring_send(r, fill, 6));

    /* try_send 4 bytes; only 2 slots remain -> must return exactly 2 */
    uint8_t data[4] = {0x22, 0x22, 0x22, 0x22};
    int written = ring_try_send(r, data, sizeof(data));
    TEST_ASSERT_EQUAL_INT(2, written);

    ring_free(r);
}

/* Producer thread used by the contention test: spam ring_send for ~50 ms */
typedef struct {
    ring_t           *r;
    volatile int      stop;
} spam_arg_t;

static void *spam_producer_thread(void *arg)
{
    spam_arg_t *a = arg;
    uint8_t burst[4] = {0xC0, 0xC1, 0xC2, 0xC3};
    while (!a->stop) {
        if (ring_send(a->r, burst, sizeof(burst)) < 0) return NULL;
    }
    return NULL;
}

/* try_send must not deadlock when the ring is heavily contended */
void test_ring_try_send_returns_quickly_under_contention(void)
{
    ring_t *r = ring_create(16);
    TEST_ASSERT_NOT_NULL(r);

    spam_arg_t sa = {.r = r, .stop = 0};
    pthread_t thr;
    pthread_create(&thr, NULL, spam_producer_thread, &sa);

    /* Drain in a loop so the producer can keep making progress */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint8_t payload[2] = {0xEE, 0xEF};
    int call_result = ring_try_send(r, payload, sizeof(payload));

    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* try_send returns 0..len, or -1 on closed (must not be closed here) */
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, call_result);
    TEST_ASSERT_LESS_OR_EQUAL_INT((int)sizeof(payload), call_result);

    long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000L
                    + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    TEST_ASSERT_LESS_THAN_INT(100, (int)elapsed_ms);

    /* Stop the producer and close the ring so it can exit cleanly.
     * ring_close wakes any producer blocked in ring_send (returns -1). */
    sa.stop = 1;
    ring_close(r);
    pthread_join(thr, NULL);

    ring_free(r);
}

/* -- NULL guard tests for ring_try_send ------------------------------------ */

/* try_send with NULL ring pointer returns -1 (not a crash) */
void test_ring_try_send_null_ring_returns_error(void)
{
    uint8_t buf[4] = {0x01, 0x02, 0x03, 0x04};
    int result = ring_try_send(NULL, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-1, result);
}

/* try_send with NULL buf and non-zero len returns -1 (not a crash) */
void test_ring_try_send_null_buf_returns_error(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);
    int result = ring_try_send(r, NULL, 4);
    TEST_ASSERT_EQUAL_INT(-1, result);
    ring_free(r);
}

/* try_send with zero len is a no-op that returns 0 (ring unchanged) */
void test_ring_try_send_zero_len_is_noop(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);
    uint8_t buf[4] = {0xAA};
    int result = ring_try_send(r, buf, 0);
    TEST_ASSERT_EQUAL_INT(0, result);
    /* Ring is still empty: a blocking recv after close must return -1 immediately. */
    ring_close(r);
    uint8_t rx[4];
    int got = ring_recv(r, rx, sizeof(rx));
    TEST_ASSERT_EQUAL_INT(-1, got);
    ring_free(r);
}

/* Wrap-around write with try_send: advance head to near end of buffer, then
 * partially drain so the ring is partially full, and verify try_send writes
 * exactly the available space via a wrapping path. */
void test_ring_try_send_wrap_around(void)
{
    const size_t CAP = 8;
    ring_t *r = ring_create(CAP);
    TEST_ASSERT_NOT_NULL(r);

    /* 1. Fill 6 bytes (head advances to 6, used=6). */
    uint8_t fill[6];
    memset(fill, 0x11, sizeof(fill));
    TEST_ASSERT_EQUAL_INT(6, ring_send(r, fill, 6));

    /* 2. Drain 4 bytes (tail advances to 4, used=2, space=6). */
    uint8_t drain[4] = {0};
    int got = 0;
    while (got < 4) {
        int n = ring_recv(r, drain + got, (size_t)(4 - got));
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        got += n;
    }
    TEST_ASSERT_EACH_EQUAL_UINT8(0x11, drain, 4);

    /* 3. try_send 2 more bytes to advance head to the last slot: head now 0
     *    (after wrapping), used=4, space=4. */
    uint8_t pre[2] = {0x22, 0x22};
    int w1 = ring_try_send(r, pre, 2);
    TEST_ASSERT_EQUAL_INT(2, w1);  /* exactly 2 written (advancing head to 8%8=0) */

    /* 4. Now try_send 6 bytes: only 4 slots available -> must write exactly 4. */
    uint8_t tx[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    int written = ring_try_send(r, tx, sizeof(tx));
    TEST_ASSERT_EQUAL_INT(4, written);

    /* Verify the ring now has 8 bytes and is full. */
    uint8_t extra = 0x99;
    int overflow = ring_try_send(r, &extra, 1);
    TEST_ASSERT_EQUAL_INT(0, overflow);  /* ring is full */

    ring_free(r);
}

/* ------------------------------------------------------------------ */
/* NEW: byte-exact preservation across multiple send/recv cycles       */

/* Verify every byte value 0x00-0xFF round-trips without corruption.   */
void test_ring_all_byte_values_preserved(void)
{
    ring_t *r = ring_create(512);
    TEST_ASSERT_NOT_NULL(r);

    uint8_t tx[256];
    for (int i = 0; i < 256; i++) tx[i] = (uint8_t)i;
    TEST_ASSERT_EQUAL_INT(256, ring_send(r, tx, 256));

    uint8_t rx[256] = {0};
    int got = 0;
    while (got < 256) {
        int n = ring_recv(r, rx + got, (size_t)(256 - got));
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        got += n;
    }
    TEST_ASSERT_EQUAL_MEMORY(tx, rx, 256);

    ring_free(r);
}

/* ring_send with zero length: should return 0 (no bytes written) and
 * leave the ring empty.  Not explicitly documented but the "write
 * exactly len bytes" contract means len=0 is trivially satisfied.    */
void test_ring_send_zero_len_is_noop(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    /* ring_send with len=0: must not block, must return 0 */
    int rc = ring_send(r, (const uint8_t *)"", 0);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Ring still empty -- close it and verify recv returns EOF */
    ring_close(r);
    uint8_t buf[4];
    TEST_ASSERT_EQUAL_INT(-1, ring_recv(r, buf, sizeof(buf)));

    ring_free(r);
}

/* After close, ring_send with zero len must return -1 (closed) and must
 * not deadlock.  The closed-flag check now runs before the while loop so
 * even a zero-length send on a closed ring is correctly refused.         */
void test_ring_send_zero_len_on_closed_ring_does_not_hang(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);
    ring_close(r);

    int rc = ring_send(r, (const uint8_t *)"", 0);
    /* Must not block and must signal closed (-1). */
    TEST_ASSERT_EQUAL_INT(-1, rc);

    ring_free(r);
}

/* Concurrent producer + consumer race: many small try_send calls
 * from a helper thread, blocking recv from main -- verify no bytes
 * are duplicated or dropped over 1000 items.                         */

typedef struct {
    ring_t   *r;
    int       n;         /* number of single-byte items to send */
    int       result;    /* 0 = ok, -1 = ring closed mid-way    */
} try_send_race_arg_t;

static void *try_send_race_producer(void *arg)
{
    try_send_race_arg_t *a = arg;
    int sent = 0;
    while (sent < a->n) {
        uint8_t b = (uint8_t)(sent & 0xFF);
        int rc = ring_try_send(a->r, &b, 1);
        if (rc == -1) { a->result = -1; return NULL; }
        if (rc == 1) sent++;
        /* rc == 0 means full or contended; retry immediately */
    }
    a->result = 0;
    return NULL;
}

void test_ring_try_send_race_no_duplication(void)
{
    const int N = 1000;
    ring_t *r = ring_create(32);
    TEST_ASSERT_NOT_NULL(r);

    try_send_race_arg_t pa = {.r = r, .n = N, .result = 99};
    pthread_t thr;
    pthread_create(&thr, NULL, try_send_race_producer, &pa);

    uint8_t buf[1];
    for (int i = 0; i < N; i++) {
        int got = ring_recv(r, buf, 1);
        TEST_ASSERT_EQUAL_INT(1, got);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(i & 0xFF), buf[0]);
    }

    pthread_join(thr, NULL);
    TEST_ASSERT_EQUAL_INT(0, pa.result);
    ring_free(r);
}

/* Repeatedly reopen and reuse the same ring: 5 sessions, each writing
 * a distinct pattern and verifying it, with no stale data leaking.   */
void test_ring_multiple_reopen_sessions(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    for (int session = 0; session < 5; session++) {
        if (session > 0) ring_reopen(r);

        uint8_t tx[8];
        memset(tx, (int)('A' + session), sizeof(tx));
        TEST_ASSERT_EQUAL_INT(8, ring_send(r, tx, 8));

        uint8_t rx[8] = {0};
        int got = 0;
        while (got < 8) {
            int n = ring_recv(r, rx + got, (size_t)(8 - got));
            TEST_ASSERT_GREATER_THAN_INT(0, n);
            got += n;
        }
        TEST_ASSERT_EACH_EQUAL_UINT8((uint8_t)('A' + session), rx, 8);

        ring_close(r);
    }

    ring_free(r);
}

/* Blocking send is unblocked when a concurrent reader drains the ring.
 * This is symmetric to test_ring_close_unblocks_recv.                */
typedef struct {
    ring_t  *r;
    size_t   n_bytes;
    int      result;
} blocking_send_arg_t;

static void *blocking_send_thread(void *arg)
{
    blocking_send_arg_t *a = arg;
    uint8_t pattern[64];
    memset(pattern, 0xBB, sizeof(pattern));
    size_t sent = 0;
    while (sent < a->n_bytes) {
        size_t chunk = a->n_bytes - sent;
        if (chunk > sizeof(pattern)) chunk = sizeof(pattern);
        int rc = ring_send(a->r, pattern, chunk);
        if (rc < 0) { a->result = -1; return NULL; }
        sent += chunk;
    }
    a->result = 0;
    return NULL;
}

void test_ring_blocking_send_unblocked_by_reader(void)
{
    const size_t TOTAL = 1024;
    ring_t *r = ring_create(16); /* tiny: forces producer to block */
    TEST_ASSERT_NOT_NULL(r);

    blocking_send_arg_t sa = {.r = r, .n_bytes = TOTAL, .result = 99};
    pthread_t thr;
    pthread_create(&thr, NULL, blocking_send_thread, &sa);

    /* Drain all TOTAL bytes; each recv unblocks the producer */
    uint8_t buf[64];
    size_t received = 0;
    while (received < TOTAL) {
        int n = ring_recv(r, buf, sizeof(buf));
        TEST_ASSERT_GREATER_THAN_INT(0, n);
        received += (size_t)n;
        for (int i = 0; i < n; i++)
            TEST_ASSERT_EQUAL_UINT8(0xBB, buf[i]);
    }

    pthread_join(thr, NULL);
    TEST_ASSERT_EQUAL_INT(0, sa.result);
    ring_free(r);
}

/* Closing a ring that is full while a sender is blocked must unblock
 * the sender and return -1.                                          */
typedef struct {
    ring_t       *r;
    int           result;
    rendezvous_t *rv;
} send_blocked_arg_t;

static void *send_into_full_ring(void *arg)
{
    send_blocked_arg_t *a = arg;
    /* Signal the main thread that we are about to block on the full ring. */
    rendezvous_signal(a->rv);
    uint8_t extra = 0xFF;
    a->result = ring_send(a->r, &extra, 1);  /* should block, then return -1 */
    return NULL;
}

void test_ring_close_unblocks_blocked_sender(void)
{
    const size_t CAP = 8;
    ring_t *r = ring_create(CAP);
    TEST_ASSERT_NOT_NULL(r);

    /* Fill the ring completely */
    uint8_t fill[8];
    memset(fill, 0xAA, sizeof(fill));
    TEST_ASSERT_EQUAL_INT(8, ring_send(r, fill, 8));

    rendezvous_t rv;
    rendezvous_init(&rv);

    /* Launch a thread that will block trying to write one more byte */
    send_blocked_arg_t sa = {.r = r, .result = 99, .rv = &rv};
    pthread_t thr;
    pthread_create(&thr, NULL, send_into_full_ring, &sa);

    rendezvous_wait(&rv); /* wait until sender is about to block, then close */
    ring_close(r);

    pthread_join(thr, NULL);
    rendezvous_destroy(&rv);
    TEST_ASSERT_EQUAL_INT(-1, sa.result);

    ring_free(r);
}

/* ring_try_send on a ring that just became closed (race): check that
 * the return is -1 and there is no crash.                            */
void test_ring_try_send_after_close_is_minus_one(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    ring_close(r);
    uint8_t b = 0x42;
    int rc = ring_try_send(r, &b, 1);
    TEST_ASSERT_EQUAL_INT(-1, rc);

    ring_free(r);
}

/* ring_recv with cap=0 must return 0 immediately (not block). */
void test_ring_recv_zero_cap_returns_zero(void)
{
    ring_t *r = ring_create(64);
    TEST_ASSERT_NOT_NULL(r);

    /* ring is empty; cap=0 must not block */
    uint8_t buf[1];
    int rc = ring_recv(r, buf, 0);
    TEST_ASSERT_EQUAL_INT(0, rc);

    ring_free(r);
}

/* ------------------------------------------------------------------ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ring_fifo_order);
    RUN_TEST(test_ring_wrap);
    RUN_TEST(test_ring_close_unblocks_recv);
    RUN_TEST(test_ring_backpressure_lossless);
    RUN_TEST(test_ring_send_on_closed_ring_returns_error);
    RUN_TEST(test_ring_recv_drains_buffered_then_returns_eof);
    /* ring_try_send tests */
    RUN_TEST(test_ring_try_send_when_empty);
    RUN_TEST(test_ring_try_send_when_full);
    RUN_TEST(test_ring_try_send_partial_when_almost_full);
    RUN_TEST(test_ring_try_send_on_closed_ring);
    /* ring_reopen tests */
    RUN_TEST(test_ring_reopen_clears_closed_flag);
    RUN_TEST(test_ring_reopen_drains_stale_data);
    RUN_TEST(test_ring_reopen_on_null_is_noop);
    RUN_TEST(test_ring_reopen_on_open_ring_is_idempotent);
    RUN_TEST(test_ring_reopen_then_recv_blocks_for_new_data);
    /* extra ring_try_send tests */
    RUN_TEST(test_ring_try_send_partial_writes_exactly_remaining_space);
    RUN_TEST(test_ring_try_send_returns_quickly_under_contention);
    /* NULL guard and edge-case tests */
    RUN_TEST(test_ring_try_send_null_ring_returns_error);
    RUN_TEST(test_ring_try_send_null_buf_returns_error);
    RUN_TEST(test_ring_try_send_zero_len_is_noop);
    RUN_TEST(test_ring_try_send_wrap_around);
    /* ring_create edge cases */
    RUN_TEST(test_ring_create_min_capacity);
    RUN_TEST(test_ring_free_null_is_safe);
    /* NEW: additional coverage */
    RUN_TEST(test_ring_all_byte_values_preserved);
    RUN_TEST(test_ring_send_zero_len_is_noop);
    RUN_TEST(test_ring_send_zero_len_on_closed_ring_does_not_hang);
    RUN_TEST(test_ring_try_send_race_no_duplication);
    RUN_TEST(test_ring_multiple_reopen_sessions);
    RUN_TEST(test_ring_blocking_send_unblocked_by_reader);
    RUN_TEST(test_ring_close_unblocks_blocked_sender);
    RUN_TEST(test_ring_try_send_after_close_is_minus_one);
    RUN_TEST(test_ring_recv_zero_cap_returns_zero);
    return UNITY_END();
}
