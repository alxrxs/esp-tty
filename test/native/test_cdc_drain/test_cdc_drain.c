/*
 * test_cdc_drain.c -- unit tests for usb_cdc_drain (native)
 *
 * Drives the drain helper with stub read functions that return a scripted
 * sequence of chunk sizes / errors and verifies:
 *   - The helper invokes read_fn the expected number of times.
 *   - Bytes are pushed to scrollback (best-effort) and the ring (non-blocking).
 *   - The helper terminates correctly on rxd == 0 and on read_fn errors.
 *   - Ring-full and ring-closed conditions do not cause infinite loops and
 *     do not stop the helper from continuing to drain.
 *
 * Compiled with -DRING_NATIVE -DUNIT_TEST so ring + scrollback use their
 * native pthread-backed implementations.
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "unity.h"
#include "usb_cdc_drain.h"
#include "ring.h"
#include "scrollback.h"

void setUp(void)    {}
void tearDown(void) {}

/* -- Scripted read_fn stub ------------------------------------------------- */

/* Hard cap on read calls to prevent any accidental infinite loop. */
#define MAX_READ_CALLS 20

typedef struct {
    /* Each step: bytes_to_return >= 0 reports that many bytes with success
     * (rxd = bytes_to_return).  bytes_to_return < 0 reports an error. */
    int   bytes_to_return[MAX_READ_CALLS];
    int   step_count;        /* number of scripted steps */
    int   call_count;        /* number of times the stub has been invoked */
    uint8_t fill_byte_base;  /* first chunk uses base, then base+1, ... */
} scripted_read_ctx_t;

static int scripted_read_cb(void *ctx, uint8_t *buf, size_t cap, size_t *rxd)
{
    scripted_read_ctx_t *c = (scripted_read_ctx_t *)ctx;

    if (c->call_count >= MAX_READ_CALLS) {
        TEST_FAIL_MESSAGE("scripted_read_cb called too many times -- drain looping");
    }
    if (c->call_count >= c->step_count) {
        TEST_FAIL_MESSAGE("scripted_read_cb called past end of script");
    }

    int step = c->bytes_to_return[c->call_count];
    c->call_count++;

    if (step < 0) {
        *rxd = 0;
        return -1;
    }

    size_t n = (size_t)step;
    if (n > cap) n = cap;
    memset(buf, (int)(c->fill_byte_base + (c->call_count - 1)), n);
    *rxd = n;
    return 0;
}

/* -- Helper: drain a ring into a flat buffer ------------------------------- */

static size_t drain_ring(ring_t *r, uint8_t *out, size_t cap)
{
    size_t total = 0;
    while (total < cap) {
        uint8_t tmp[128];
        /* Mark ring closed first via a sentinel: callers must close ring
         * before draining if they want this to terminate.  Otherwise this
         * loop would block.  We close inline. */
        int n = ring_recv(r, tmp, sizeof(tmp));
        if (n <= 0) break;
        if (total + (size_t)n > cap) n = (int)(cap - total);
        memcpy(out + total, tmp, (size_t)n);
        total += (size_t)n;
    }
    return total;
}

/* Snapshot the ring's content by closing it and draining everything. */
static size_t snapshot_ring(ring_t *r, uint8_t *out, size_t cap)
{
    ring_close(r);
    return drain_ring(r, out, cap);
}

/* -- Test 1 ---------------------------------------------------------------- */

void test_drain_consumes_until_read_returns_zero(void)
{
    scripted_read_ctx_t rctx = {
        .bytes_to_return = {64, 64, 32, 0},
        .step_count      = 4,
        .call_count      = 0,
        .fill_byte_base  = 0x10,
    };

    ring_t       *ring = ring_create(512);
    scrollback_t *sb   = scrollback_create(1024);
    TEST_ASSERT_NOT_NULL(ring);
    TEST_ASSERT_NOT_NULL(sb);

    int rc = usb_cdc_drain(scripted_read_cb, &rctx, ring, sb);

    TEST_ASSERT_EQUAL_INT(4, rctx.call_count);
    TEST_ASSERT_EQUAL_INT(160, rc);  /* total bytes drained */

    /* Ring should hold all 160 bytes (capacity 512 > 160). */
    uint8_t ring_buf[512];
    size_t ring_len = snapshot_ring(ring, ring_buf, sizeof(ring_buf));
    TEST_ASSERT_EQUAL_size_t(160, ring_len);

    /* Scrollback should also hold all 160 bytes. */
    size_t sb_len = 0;
    uint8_t *sb_dump = scrollback_get_lines(sb, 100000, &sb_len);
    TEST_ASSERT_NOT_NULL(sb_dump);
    TEST_ASSERT_EQUAL_size_t(160, sb_len);

    free(sb_dump);
    ring_free(ring);
    free(sb);
}

/* -- Test 2 ---------------------------------------------------------------- */

void test_drain_single_chunk_under_64_bytes(void)
{
    scripted_read_ctx_t rctx = {
        .bytes_to_return = {17, 0},
        .step_count      = 2,
        .call_count      = 0,
        .fill_byte_base  = 0xAB,
    };

    ring_t       *ring = ring_create(256);
    scrollback_t *sb   = scrollback_create(512);
    TEST_ASSERT_NOT_NULL(ring);
    TEST_ASSERT_NOT_NULL(sb);

    int rc = usb_cdc_drain(scripted_read_cb, &rctx, ring, sb);

    TEST_ASSERT_EQUAL_INT(2, rctx.call_count);   /* 17, then 0 */
    TEST_ASSERT_EQUAL_INT(17, rc);

    /* Ring should hold exactly 17 bytes of 0xAB. */
    uint8_t ring_buf[64];
    size_t ring_len = snapshot_ring(ring, ring_buf, sizeof(ring_buf));
    TEST_ASSERT_EQUAL_size_t(17, ring_len);
    for (size_t i = 0; i < ring_len; i++)
        TEST_ASSERT_EQUAL_UINT8(0xAB, ring_buf[i]);

    /* Scrollback holds 17 bytes. */
    size_t sb_len = 0;
    uint8_t *sb_dump = scrollback_get_lines(sb, 100000, &sb_len);
    TEST_ASSERT_NOT_NULL(sb_dump);
    TEST_ASSERT_EQUAL_size_t(17, sb_len);

    free(sb_dump);
    ring_free(ring);
    free(sb);
}

/* -- Test 3 ---------------------------------------------------------------- */

void test_drain_stops_on_read_error(void)
{
    scripted_read_ctx_t rctx = {
        .bytes_to_return = {50, -1},   /* call 1: 50 bytes OK; call 2: error */
        .step_count      = 2,
        .call_count      = 0,
        .fill_byte_base  = 0x42,
    };

    ring_t       *ring = ring_create(256);
    scrollback_t *sb   = scrollback_create(512);
    TEST_ASSERT_NOT_NULL(ring);
    TEST_ASSERT_NOT_NULL(sb);

    int rc = usb_cdc_drain(scripted_read_cb, &rctx, ring, sb);

    /* Helper returns -1 to signal the read error (documented convention). */
    TEST_ASSERT_EQUAL_INT(-1, rc);

    /* Exactly two calls: the 50-byte read and the failing read.  Stub will
     * TEST_FAIL if called a third time. */
    TEST_ASSERT_EQUAL_INT(2, rctx.call_count);

    /* Ring still holds the 50 bytes from call 1 (the chunk was pushed
     * before the error was observed). */
    uint8_t ring_buf[256];
    size_t ring_len = snapshot_ring(ring, ring_buf, sizeof(ring_buf));
    TEST_ASSERT_EQUAL_size_t(50, ring_len);

    /* Scrollback also has the 50 bytes from call 1. */
    size_t sb_len = 0;
    uint8_t *sb_dump = scrollback_get_lines(sb, 100000, &sb_len);
    TEST_ASSERT_NOT_NULL(sb_dump);
    TEST_ASSERT_EQUAL_size_t(50, sb_len);

    free(sb_dump);
    ring_free(ring);
    free(sb);
}

/* -- Test 4 ---------------------------------------------------------------- */

void test_drain_continues_when_ring_full_partial_write(void)
{
    scripted_read_ctx_t rctx = {
        .bytes_to_return = {64, 0},
        .step_count      = 2,
        .call_count      = 0,
        .fill_byte_base  = 0x55,
    };

    /* Tiny ring (cap 8) pre-filled with 6 bytes -- only 2 bytes of space free. */
    ring_t *ring = ring_create(8);
    TEST_ASSERT_NOT_NULL(ring);
    uint8_t preload[6] = {1, 2, 3, 4, 5, 6};
    TEST_ASSERT_EQUAL_INT(6, ring_try_send(ring, preload, sizeof(preload)));

    scrollback_t *sb = scrollback_create(512);
    TEST_ASSERT_NOT_NULL(sb);

    int rc = usb_cdc_drain(scripted_read_cb, &rctx, ring, sb);

    TEST_ASSERT_EQUAL_INT(2, rctx.call_count);
    /* Return value is "bytes drained from source" (64), not "bytes pushed
     * into the ring".  The ring-full condition silently drops 62 bytes; the
     * scrollback captures all of them. */
    TEST_ASSERT_EQUAL_INT(64, rc);

    /* Ring contains the original 6 bytes + 2 bytes (0x55) that fit. */
    uint8_t ring_buf[16];
    size_t ring_len = snapshot_ring(ring, ring_buf, sizeof(ring_buf));
    TEST_ASSERT_EQUAL_size_t(8, ring_len);
    TEST_ASSERT_EQUAL_MEMORY(preload, ring_buf, 6);
    TEST_ASSERT_EQUAL_UINT8(0x55, ring_buf[6]);
    TEST_ASSERT_EQUAL_UINT8(0x55, ring_buf[7]);

    /* Scrollback gets all 64 bytes (push happens before ring_try_send). */
    size_t sb_len = 0;
    uint8_t *sb_dump = scrollback_get_lines(sb, 100000, &sb_len);
    TEST_ASSERT_NOT_NULL(sb_dump);
    TEST_ASSERT_EQUAL_size_t(64, sb_len);

    free(sb_dump);
    ring_free(ring);
    free(sb);
}

/* -- Test 5 ---------------------------------------------------------------- */

void test_drain_continues_when_ring_closed(void)
{
    scripted_read_ctx_t rctx = {
        .bytes_to_return = {30, 0},
        .step_count      = 2,
        .call_count      = 0,
        .fill_byte_base  = 0x77,
    };

    ring_t *ring = ring_create(256);
    TEST_ASSERT_NOT_NULL(ring);
    ring_close(ring);   /* close before draining */

    scrollback_t *sb = scrollback_create(512);
    TEST_ASSERT_NOT_NULL(sb);

    int rc = usb_cdc_drain(scripted_read_cb, &rctx, ring, sb);

    TEST_ASSERT_EQUAL_INT(2, rctx.call_count);
    TEST_ASSERT_EQUAL_INT(30, rc);  /* 30 bytes drained from source */

    /* Scrollback got the 30 bytes. */
    size_t sb_len = 0;
    uint8_t *sb_dump = scrollback_get_lines(sb, 100000, &sb_len);
    TEST_ASSERT_NOT_NULL(sb_dump);
    TEST_ASSERT_EQUAL_size_t(30, sb_len);
    for (size_t i = 0; i < sb_len; i++)
        TEST_ASSERT_EQUAL_UINT8(0x77, sb_dump[i]);

    /* Ring stayed closed: ring_try_send returns -1 immediately, so no data
     * was queued.  Verify by trying to send something: closed ring returns
     * -1, confirming closed state.  ring_recv on a closed empty ring also
     * returns -1 (no data). */
    uint8_t one = 0;
    TEST_ASSERT_EQUAL_INT(-1, ring_try_send(ring, &one, 1));

    uint8_t tmp[16];
    TEST_ASSERT_EQUAL_INT(-1, ring_recv(ring, tmp, sizeof(tmp)));

    free(sb_dump);
    ring_free(ring);
    free(sb);
}

/* -- Test 6 ---------------------------------------------------------------- */

void test_drain_handles_zero_first_call(void)
{
    scripted_read_ctx_t rctx = {
        .bytes_to_return = {0},
        .step_count      = 1,
        .call_count      = 0,
        .fill_byte_base  = 0x00,
    };

    ring_t       *ring = ring_create(64);
    scrollback_t *sb   = scrollback_create(128);
    TEST_ASSERT_NOT_NULL(ring);
    TEST_ASSERT_NOT_NULL(sb);

    int rc = usb_cdc_drain(scripted_read_cb, &rctx, ring, sb);

    TEST_ASSERT_EQUAL_INT(1, rctx.call_count);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Ring is empty. */
    uint8_t ring_buf[16];
    size_t ring_len = snapshot_ring(ring, ring_buf, sizeof(ring_buf));
    TEST_ASSERT_EQUAL_size_t(0, ring_len);

    /* Scrollback is empty -- no push was performed. */
    size_t sb_len = 99;
    uint8_t *sb_dump = scrollback_get_lines(sb, 100000, &sb_len);
    TEST_ASSERT_NULL(sb_dump);
    TEST_ASSERT_EQUAL_size_t(0, sb_len);

    ring_free(ring);
    free(sb);
}

/* -- Main ------------------------------------------------------------------ */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_drain_consumes_until_read_returns_zero);
    RUN_TEST(test_drain_single_chunk_under_64_bytes);
    RUN_TEST(test_drain_stops_on_read_error);
    RUN_TEST(test_drain_continues_when_ring_full_partial_write);
    RUN_TEST(test_drain_continues_when_ring_closed);
    RUN_TEST(test_drain_handles_zero_first_call);
    return UNITY_END();
}
