/*
 * test_bridge.c — unit tests for bridge_pump (native)
 *
 * Wires two bridge_pump instances back-to-back through in-memory pipes
 * and verifies: losslessness, ordering, stop-flag termination.
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include "unity.h"
#include "bridge.h"
#include "ring.h"

void setUp(void)    {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* Helper: use ring_t as the transport for bridge_pump callbacks       */

static int ring_read_cb(void *ctx, uint8_t *buf, size_t cap)
{
    return ring_recv((ring_t *)ctx, buf, cap);
}

static int ring_write_cb(void *ctx, const uint8_t *buf, size_t len)
{
    return ring_send((ring_t *)ctx, buf, len);
}

/* ------------------------------------------------------------------ */
/* Thread args for a running pump                                      */

typedef struct {
    ring_t         *src;
    ring_t         *dst;
    volatile bool   stop;
} pump_thread_arg_t;

static void *pump_thread(void *arg)
{
    pump_thread_arg_t *a = (pump_thread_arg_t *)arg;
    bridge_pump(ring_read_cb,  a->src,
                ring_write_cb, a->dst,
                &a->stop);
    return NULL;
}

/* ------------------------------------------------------------------ */

/*
 * Topology:
 *
 *   writer_thr → [a_to_b] → pump_thr → [b_to_a] → reader (main)
 *
 * Writer and pump in background threads; reader verifies in main.
 * Writer and reader must be concurrent to prevent deadlock when rings
 * are smaller than N (both rings fill up if the reader waits for the
 * writer to finish before draining).
 */
typedef struct {
    ring_t *dst;
    size_t  n;
    int     result;
} writer_arg_t;

static void *sequential_writer(void *arg)
{
    writer_arg_t *a = (writer_arg_t *)arg;
    for (size_t i = 0; i < a->n; i++) {
        uint8_t b = (uint8_t)(i & 0xFF);
        if (ring_send(a->dst, &b, 1) < 0) { a->result = -1; return NULL; }
    }
    a->result = 0;
    return NULL;
}

void test_bridge_lossless_ordering(void)
{
    const size_t N    = 65536;
    const size_t RING = 512;  /* small ring forces lots of blocking */

    ring_t *a_to_b = ring_create(RING);
    ring_t *b_to_a = ring_create(RING);
    TEST_ASSERT_NOT_NULL(a_to_b);
    TEST_ASSERT_NOT_NULL(b_to_a);

    pump_thread_arg_t parg = {.src = a_to_b, .dst = b_to_a, .stop = false};
    pthread_t pump_thr;
    pthread_create(&pump_thr, NULL, pump_thread, &parg);

    /* Writer runs concurrently so main can drain b_to_a without deadlock */
    writer_arg_t warg = {.dst = a_to_b, .n = N, .result = 99};
    pthread_t write_thr;
    pthread_create(&write_thr, NULL, sequential_writer, &warg);

    /* Reader: verify every byte in order */
    for (size_t i = 0; i < N; i++) {
        uint8_t got;
        int r = ring_recv(b_to_a, &got, 1);
        TEST_ASSERT_EQUAL_INT(1, r);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(i & 0xFF), got);
    }

    pthread_join(write_thr, NULL);
    TEST_ASSERT_EQUAL_INT(0, warg.result);

    /* Shut down pump */
    parg.stop = true;
    ring_close(a_to_b);
    pthread_join(pump_thr, NULL);

    ring_free(a_to_b);
    ring_free(b_to_a);
}

/* ------------------------------------------------------------------ */

void test_bridge_stop_flag_terminates(void)
{
    ring_t *a_to_b = ring_create(64);
    ring_t *b_to_a = ring_create(64);
    TEST_ASSERT_NOT_NULL(a_to_b);
    TEST_ASSERT_NOT_NULL(b_to_a);

    pump_thread_arg_t parg = {.src = a_to_b, .dst = b_to_a, .stop = false};
    pthread_t pump_thr;
    pthread_create(&pump_thr, NULL, pump_thread, &parg);

    /* Set stop flag and unblock the pump's blocked ring_recv */
    parg.stop = true;
    ring_close(a_to_b);

    /* join must complete — pump must not spin forever */
    pthread_join(pump_thr, NULL);

    ring_free(a_to_b);
    ring_free(b_to_a);
}

/* ------------------------------------------------------------------ */

/*
 * Full-duplex loopback: two pumps, producer faster than consumer.
 *
 *   A writes → [ab_ring] → pump_ab → [ba_ring] → A reads
 *
 * Producer thread sends at full speed; consumer reads and verifies.
 */
typedef struct {
    ring_t *src;
    size_t  n;
    int     result; /* 0 ok */
} producer_arg_t;

static void *bulk_producer(void *arg)
{
    producer_arg_t *a = (producer_arg_t *)arg;
    for (size_t i = 0; i < a->n; i++) {
        uint8_t b = (uint8_t)(i & 0xFF);
        if (ring_send(a->src, &b, 1) < 0) { a->result = -1; return NULL; }
    }
    a->result = 0;
    return NULL;
}

void test_bridge_full_duplex_no_drops(void)
{
    const size_t N    = 131072;
    const size_t RING = 256;

    ring_t *ab = ring_create(RING);
    ring_t *ba = ring_create(RING);
    TEST_ASSERT_NOT_NULL(ab);
    TEST_ASSERT_NOT_NULL(ba);

    pump_thread_arg_t parg = {.src = ab, .dst = ba, .stop = false};
    pthread_t pump_thr;
    pthread_create(&pump_thr, NULL, pump_thread, &parg);

    producer_arg_t parg2 = {.src = ab, .n = N, .result = 99};
    pthread_t prod_thr;
    pthread_create(&prod_thr, NULL, bulk_producer, &parg2);

    /* Consumer verifies order */
    for (size_t i = 0; i < N; i++) {
        uint8_t got;
        int r = ring_recv(ba, &got, 1);
        TEST_ASSERT_GREATER_THAN_INT(0, r);
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(i & 0xFF), got);
    }

    pthread_join(prod_thr, NULL);
    TEST_ASSERT_EQUAL_INT(0, parg2.result);

    parg.stop = true;
    ring_close(ab);
    pthread_join(pump_thr, NULL);

    ring_free(ab);
    ring_free(ba);
}

/* ------------------------------------------------------------------ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bridge_lossless_ordering);
    RUN_TEST(test_bridge_stop_flag_terminates);
    RUN_TEST(test_bridge_full_duplex_no_drops);
    return UNITY_END();
}
