/*
 * test_ring.c — unit tests for ring buffer (native, RING_NATIVE=1)
 *
 * Tests: FIFO correctness, blocking semantics, wrap-around, close.
 * Compiled with -DRING_NATIVE=1 by the PlatformIO native environment.
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "unity.h"
#include "ring.h"

/* ------------------------------------------------------------------ */
void setUp(void)    {}
void tearDown(void) {}
/* ------------------------------------------------------------------ */

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

    /* Fill buffer, drain half, fill again — forces wrap-around */
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

typedef struct { ring_t *r; int result; } recv_arg_t;

static void *blocked_recv_thread(void *arg)
{
    recv_arg_t *a = arg;
    uint8_t buf[4];
    a->result = ring_recv(a->r, buf, sizeof(buf));
    return NULL;
}

void test_ring_close_unblocks_recv(void)
{
    ring_t *r = ring_create(16);
    TEST_ASSERT_NOT_NULL(r);

    recv_arg_t arg = {.r = r, .result = 0};
    pthread_t thr;
    pthread_create(&thr, NULL, blocked_recv_thread, &arg);

    usleep(20000); /* let thread block */
    ring_close(r);

    pthread_join(thr, NULL);
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
 * single-session SSH teardown (bridge_pump → ring_close → pump tasks exit),
 * at which point buffered data is already destined to be discarded.  Testing
 * the FreeRTOS side would require target hardware and would require modifying
 * the FreeRTOS backend — both are out of scope per the project hard constraints.
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

    /* Second recv: buffer is empty and ring is closed → EOF */
    int eof = ring_recv(r, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-1, eof);

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
    return UNITY_END();
}
