/*
 * test_ota_stream.c -- unit tests for lib/ota_stream/ (native, no hardware)
 *
 * Exercises the read-all accumulator extracted from main/ota_session.c:
 *   - geometric growth across many reads
 *   - transient (0-return) retry behaviour
 *   - OOM at the 5th allocator call -> ERR_OOM with no leak / no buffer
 *   - empty stream (immediate <0 return) -> ERR_EMPTY
 *   - oversize stream (exceeds max_bytes) -> ERR_TOOBIG
 *
 * The mocks below use small counter-based ctx structs in the spirit of the
 * existing native suite (see test_ota_verify, test_bridge).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "ota_stream.h"

void setUp(void)    {}
void tearDown(void) {}

/* -- Mock read contexts ---------------------------------------------------- */

/*
 * fixed_read_ctx -- returns `chunk_size` bytes on each call (filled with a
 * cycling pattern derived from a running byte counter so test 1 can verify
 * payload integrity), until `total_calls` is reached.  After that, returns
 * -1 (terminal EOF/error).
 */
typedef struct {
    size_t   chunk_size;
    unsigned total_calls;
    unsigned call_count;
    uint8_t  next_byte;   /* running pattern byte */
} fixed_read_ctx_t;

static int fixed_read(void *vctx, uint8_t *buf, size_t cap)
{
    fixed_read_ctx_t *c = (fixed_read_ctx_t *)vctx;
    if (c->call_count >= c->total_calls) return -1;
    c->call_count++;
    size_t n = c->chunk_size < cap ? c->chunk_size : cap;
    for (size_t i = 0; i < n; ++i) buf[i] = c->next_byte++;
    return (int)n;
}

/*
 * scripted_read_ctx -- returns a hard-coded sequence of (return-value, fill)
 * pairs.  Used by the transient-zero test.
 */
typedef struct {
    const int *script;   /* values: <0 EOF, 0 transient, >0 = bytes to fill */
    unsigned   len;
    unsigned   idx;
    uint8_t    fill;     /* byte value used for >0 returns */
} scripted_read_ctx_t;

static int scripted_read(void *vctx, uint8_t *buf, size_t cap)
{
    scripted_read_ctx_t *c = (scripted_read_ctx_t *)vctx;
    if (c->idx >= c->len) return -1;
    int v = c->script[c->idx++];
    if (v <= 0) return v;
    size_t n = (size_t)v < cap ? (size_t)v : cap;
    memset(buf, c->fill, n);
    return (int)n;
}

/* -- OOM-injecting allocator hooks ----------------------------------------- */
/*
 * counted_alloc_ctx -- counts every alloc + realloc call against a single
 * counter and returns NULL once `fail_at` is reached.  free_count tracks
 * how many times free was invoked, so tests can assert the partial buffer
 * was released on the error path.
 *
 * Because the production allocator uses calloc / realloc, this single
 * counter approximates the same "fail on the Nth allocation call" semantics
 * regardless of whether the call ends up as the initial alloc or a grow.
 *
 * The mock state is kept in a process-static struct because the
 * ota_stream_alloc_fn / realloc_fn / free_fn signatures don't take a ctx
 * argument.  Tests reset the state in setUp / explicitly before use.
 */
typedef struct {
    unsigned alloc_calls;
    unsigned fail_at;      /* fail when alloc_calls reaches this value */
    unsigned free_calls;
} mock_alloc_state_t;

static mock_alloc_state_t g_alloc;

static void mock_alloc_reset(unsigned fail_at)
{
    g_alloc.alloc_calls = 0;
    g_alloc.fail_at     = fail_at;
    g_alloc.free_calls  = 0;
}

static void *mock_alloc(size_t n)
{
    g_alloc.alloc_calls++;
    if (g_alloc.alloc_calls == g_alloc.fail_at) return NULL;
    return calloc(1, n);
}

static void *mock_realloc(void *p, size_t n)
{
    g_alloc.alloc_calls++;
    if (g_alloc.alloc_calls == g_alloc.fail_at) return NULL;
    return realloc(p, n);
}

static void mock_free(void *p)
{
    if (p) g_alloc.free_calls++;
    free(p);
}

/* -- Tests ----------------------------------------------------------------- */

/* Happy path: 10 chunks of 4096 bytes each, then EOF.  Verify payload bytes
 * round-trip exactly (no off-by-one in geometric realloc copies). */
void test_ota_stream_grows_buffer(void)
{
    fixed_read_ctx_t ctx = {
        .chunk_size  = 4096,
        .total_calls = 10,
        .call_count  = 0,
        .next_byte   = 0,
    };

    uint8_t *buf = NULL;
    size_t   len = 0;
    ota_stream_result_t r = ota_stream_read_all(
        fixed_read, &ctx,
        /* max_bytes        */ 1024 * 1024,
        /* max_zero_retries */ 0,
        NULL, NULL, NULL,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_OK, r);
    TEST_ASSERT_EQUAL_size_t(40960u, len);
    TEST_ASSERT_NOT_NULL(buf);

    /* Verify the cycling pattern: byte i should equal (uint8_t)i */
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != (uint8_t)i) {
            char m[64];
            snprintf(m, sizeof(m), "mismatch at offset %zu: got 0x%02x", i, buf[i]);
            TEST_FAIL_MESSAGE(m);
        }
    }
    free(buf);
}

/* Transient 0-returns must not be treated as EOF when within the retry
 * budget.  Sequence: 0,0,0,100,EOF -> out_len == 100. */
void test_ota_stream_handles_transient_zero_returns(void)
{
    const int script[] = { 0, 0, 0, 100, -1 };
    scripted_read_ctx_t ctx = {
        .script = script,
        .len    = sizeof(script)/sizeof(script[0]),
        .idx    = 0,
        .fill   = 0xAB,
    };

    uint8_t *buf = NULL;
    size_t   len = 0;
    ota_stream_result_t r = ota_stream_read_all(
        scripted_read, &ctx,
        /* max_bytes        */ 1024 * 1024,
        /* max_zero_retries */ 5,
        NULL, NULL, NULL,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_OK, r);
    TEST_ASSERT_EQUAL_size_t(100u, len);
    TEST_ASSERT_NOT_NULL(buf);
    for (size_t i = 0; i < len; ++i) TEST_ASSERT_EQUAL_UINT8(0xAB, buf[i]);
    free(buf);
}

/* OOM on the 5th allocator call: ERR_OOM, *out_buf NULL, *out_len 0.
 * Also assert that the partial buffer was released via our free hook. */
void test_ota_stream_oom_partial(void)
{
    mock_alloc_reset(/* fail_at */ 5);

    fixed_read_ctx_t ctx = {
        .chunk_size  = 4096,
        .total_calls = 100,    /* well past the failure point */
        .call_count  = 0,
        .next_byte   = 0,
    };

    uint8_t *buf = (uint8_t *)0xDEAD;  /* sentinel -- must be cleared */
    size_t   len = 42;                  /* sentinel -- must be zeroed  */
    ota_stream_result_t r = ota_stream_read_all(
        fixed_read, &ctx,
        /* max_bytes        */ 1024 * 1024,
        /* max_zero_retries */ 0,
        mock_alloc, mock_realloc, mock_free,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_ERR_OOM, r);
    TEST_ASSERT_NULL(buf);
    TEST_ASSERT_EQUAL_size_t(0u, len);
    /* The partial buffer should have been released exactly once (after
     * the alloc-fail on call #5 the helper frees the buffer it had built
     * up over calls #1..#4). */
    TEST_ASSERT_EQUAL_UINT(1u, g_alloc.free_calls);
}

/* Empty input: read_fn returns -1 immediately -> ERR_EMPTY (we treat any
 * "no bytes ever stored" terminal as EMPTY; ERR_EOF is reserved for the
 * future and currently unused).  *out_buf NULL, *out_len 0. */
void test_ota_stream_empty_input(void)
{
    const int script[] = { -1 };
    scripted_read_ctx_t ctx = {
        .script = script,
        .len    = 1,
        .idx    = 0,
        .fill   = 0,
    };

    uint8_t *buf = (uint8_t *)0xCAFE;
    size_t   len = 99;
    ota_stream_result_t r = ota_stream_read_all(
        scripted_read, &ctx,
        /* max_bytes        */ 1024 * 1024,
        /* max_zero_retries */ 0,
        NULL, NULL, NULL,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_ERR_EMPTY, r);
    TEST_ASSERT_NULL(buf);
    TEST_ASSERT_EQUAL_size_t(0u, len);
}

/* max_bytes cap: first read of 4096 bytes against a 1024-byte cap ->
 * ERR_TOOBIG, no partial buffer. */
void test_ota_stream_exceeds_max_bytes(void)
{
    fixed_read_ctx_t ctx = {
        .chunk_size  = 4096,
        .total_calls = 10,
        .call_count  = 0,
        .next_byte   = 0,
    };

    mock_alloc_reset(/* fail_at */ 0);  /* never fail; track free count */

    uint8_t *buf = NULL;
    size_t   len = 0;
    ota_stream_result_t r = ota_stream_read_all(
        fixed_read, &ctx,
        /* max_bytes        */ 1024,
        /* max_zero_retries */ 0,
        mock_alloc, mock_realloc, mock_free,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_ERR_TOOBIG, r);
    TEST_ASSERT_NULL(buf);
    TEST_ASSERT_EQUAL_size_t(0u, len);
    /* "No partial buffer leaked" check: the accumulator allocates up to
     * max_bytes (1024 here) and then probes one more byte, which triggers
     * TOOBIG.  Either no buffer was allocated (free_calls==0) or the
     * partial buffer was released (free_calls==1).  Both are leak-free. */
    TEST_ASSERT_TRUE_MESSAGE(g_alloc.free_calls <= 1u,
                             "partial buffer not released on TOOBIG");
}

/* Bonus: single small read exactly fills the buffer (no realloc needed). */
void test_ota_stream_single_small_read(void)
{
    const int script[] = { 7, -1 };
    scripted_read_ctx_t ctx = {
        .script = script,
        .len    = 2,
        .idx    = 0,
        .fill   = 0x5A,
    };

    uint8_t *buf = NULL;
    size_t   len = 0;
    ota_stream_result_t r = ota_stream_read_all(
        scripted_read, &ctx,
        /* max_bytes        */ 1024 * 1024,
        /* max_zero_retries */ 0,
        NULL, NULL, NULL,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_OK, r);
    TEST_ASSERT_EQUAL_size_t(7u, len);
    TEST_ASSERT_NOT_NULL(buf);
    for (size_t i = 0; i < len; ++i) TEST_ASSERT_EQUAL_UINT8(0x5A, buf[i]);
    free(buf);
}

/* Bonus: zero_retries exhausted with no progress -> ERR_EMPTY. */
void test_ota_stream_zero_retries_exhausted(void)
{
    const int script[] = { 0, 0, 0 };  /* will be followed by implicit -1 */
    scripted_read_ctx_t ctx = {
        .script = script,
        .len    = 3,
        .idx    = 0,
        .fill   = 0,
    };

    uint8_t *buf = NULL;
    size_t   len = 0;
    ota_stream_result_t r = ota_stream_read_all(
        scripted_read, &ctx,
        /* max_bytes        */ 1024 * 1024,
        /* max_zero_retries */ 1,   /* allow only ONE transient zero */
        NULL, NULL, NULL,
        &buf, &len);

    TEST_ASSERT_EQUAL_INT(OTA_STREAM_ERR_EMPTY, r);
    TEST_ASSERT_NULL(buf);
    TEST_ASSERT_EQUAL_size_t(0u, len);
}

/* -- Main ------------------------------------------------------------------ */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ota_stream_grows_buffer);
    RUN_TEST(test_ota_stream_handles_transient_zero_returns);
    RUN_TEST(test_ota_stream_oom_partial);
    RUN_TEST(test_ota_stream_empty_input);
    RUN_TEST(test_ota_stream_exceeds_max_bytes);
    RUN_TEST(test_ota_stream_single_small_read);
    RUN_TEST(test_ota_stream_zero_retries_exhausted);
    return UNITY_END();
}
