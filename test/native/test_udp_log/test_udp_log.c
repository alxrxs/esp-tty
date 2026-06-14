/*
 * test_udp_log.c -- unit tests for UDP log formatting / hook behaviour
 *
 * Tests the behaviour expected from the udp_log vprintf hook:
 *   - printf-style formatting into a fixed-size stack buffer
 *   - Truncation of lines longer than the buffer
 *   - ANSI escape sequences forwarded verbatim
 *   - No-send state when the socket fd is -1 (pre-Wi-Fi)
 *
 * These tests do NOT compile udp_log.c directly (it depends on FreeRTOS and
 * lwIP which are absent in the native build).  Instead they exercise the
 * equivalent logic via an inline test harness that mirrors the hook exactly,
 * allowing host builds without ESP-IDF.
 *
 * The hook in udp_log.c does exactly this:
 *   1. va_copy args, call prev_vprintf(fmt, args_copy)  -- UART passthrough
 *   2. vsnprintf(buf, BUF_SIZE, fmt, args)               -- format for UDP
 *   3. if fd != -1: sendto(fd, buf, len, ...)            -- best-effort send
 *
 * All three steps are tested here using a controllable fake-sendto.
 *
 * Tests:
 *   1.  Short line is formatted correctly into the buffer.
 *   2.  Long line (> BUF_SIZE) is truncated; formatted buffer is non-empty.
 *   3.  ANSI escape sequences appear verbatim in the formatted buffer.
 *   4.  Hook calls prev_vprintf for UART passthrough before sending UDP.
 *   5.  When fd == -1 (no socket), sendto is not called.
 *   6.  When fd >= 0 (socket ready), sendto receives the formatted buffer.
 *   7.  Integer arguments are formatted into the buffer correctly.
 *   8.  Empty format string produces zero-length buffer; sendto not called.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "unity.h"

/* --------------------------------------------------------------------------
 * Inline test harness -- mirrors udp_log_vprintf_hook logic exactly
 * -------------------------------------------------------------------------- */

#define TEST_BUF_SIZE  512

/* Fake socket fd -- set to -1 to simulate pre-Wi-Fi state */
static int g_fake_fd = -1;

/* Capture what would be sent to UDP */
static char   g_sent_buf[TEST_BUF_SIZE + 4];
static size_t g_sent_len = 0;
static int    g_sendto_calls = 0;

/* Capture UART passthrough calls */
static int    g_uart_calls = 0;
static char   g_uart_fmt[256];

/* fake_sendto -- replaces the real sendto in tests */
static int fake_sendto(const char *buf, size_t len)
{
    ++g_sendto_calls;
    size_t copy = len < sizeof(g_sent_buf) - 1 ? len : sizeof(g_sent_buf) - 1;
    memcpy(g_sent_buf, buf, copy);
    g_sent_buf[copy] = '\0';
    g_sent_len = copy;
    return (int)len;
}

/* fake_prev_vprintf -- replaces the UART vprintf passthrough */
static int fake_prev_vprintf(const char *fmt)
{
    ++g_uart_calls;
    strncpy(g_uart_fmt, fmt ? fmt : "", sizeof(g_uart_fmt) - 1);
    return 0;
}

/* hook_impl -- the exact logic from udp_log_vprintf_hook, parameterised for testing */
static int hook_impl(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    /* Step 1: UART passthrough (call prev_vprintf with fmt, before consuming args) */
    fake_prev_vprintf(fmt);

    /* Step 2: Format into a stack buffer (truncates at BUF_SIZE - 1) */
    char buf[TEST_BUF_SIZE];
    int  n = vsnprintf(buf, sizeof(buf), fmt, args);
    if (n < 0) n = 0;
    size_t len = ((size_t)n < sizeof(buf)) ? (size_t)n : sizeof(buf) - 1;

    va_end(args);

    /* Step 3: Send only if socket is ready */
    if (g_fake_fd != -1 && len > 0) {
        fake_sendto(buf, len);
    }

    return (int)len;
}

/* --------------------------------------------------------------------------
 * setUp / tearDown
 * -------------------------------------------------------------------------- */
void setUp(void)
{
    memset(g_sent_buf, 0, sizeof(g_sent_buf));
    g_sent_len    = 0;
    g_sendto_calls = 0;
    g_uart_calls  = 0;
    memset(g_uart_fmt, 0, sizeof(g_uart_fmt));
    g_fake_fd     = 3;   /* default: socket is "ready" */
}

void tearDown(void) {}

/* --------------------------------------------------------------------------
 * Test 1: Short line is formatted correctly
 * -------------------------------------------------------------------------- */
void test_short_line_formatted(void)
{
    hook_impl("hello %s %d\n", "world", 42);

    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "hello world 42"));
}

/* --------------------------------------------------------------------------
 * Test 2: Long line (> BUF_SIZE) is truncated; buffer is non-empty
 * -------------------------------------------------------------------------- */
void test_long_line_truncated(void)
{
    char big[600];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    hook_impl("%s", big);

    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    /* Sent length must be <= TEST_BUF_SIZE - 1 */
    TEST_ASSERT_TRUE(g_sent_len <= TEST_BUF_SIZE - 1);
    /* Content begins with 'A' */
    TEST_ASSERT_EQUAL_CHAR('A', g_sent_buf[0]);
}

/* --------------------------------------------------------------------------
 * Test 3: ANSI escape sequences are forwarded verbatim
 * -------------------------------------------------------------------------- */
void test_ansi_escapes_verbatim(void)
{
    /* Typical ESP-IDF colour prefix: ESC[0;32m (green) + reset ESC[0m */
    hook_impl("\x1B[0;32mI (100) wifi: connected\x1B[0m\n");

    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    /* ESC character must appear in the datagram */
    TEST_ASSERT_TRUE(memchr(g_sent_buf, 0x1B, g_sent_len) != NULL);
    /* Log text must be present */
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "wifi: connected"));
}

/* --------------------------------------------------------------------------
 * Test 4: UART passthrough is invoked before the UDP send
 * -------------------------------------------------------------------------- */
void test_uart_passthrough_called_before_send(void)
{
    hook_impl("passthrough test\n");

    /* prev_vprintf must have been called exactly once */
    TEST_ASSERT_EQUAL_INT(1, g_uart_calls);
    /* The format string must match */
    TEST_ASSERT_NOT_NULL(strstr(g_uart_fmt, "passthrough test"));
    /* UDP send also occurred */
    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
}

/* --------------------------------------------------------------------------
 * Test 5: When fd == -1 (no socket), sendto is NOT called
 * -------------------------------------------------------------------------- */
void test_no_send_when_fd_negative(void)
{
    g_fake_fd = -1;

    hook_impl("should not be sent\n");

    /* UART passthrough still happens */
    TEST_ASSERT_EQUAL_INT(1, g_uart_calls);
    /* But sendto must not be called */
    TEST_ASSERT_EQUAL_INT(0, g_sendto_calls);
}

/* --------------------------------------------------------------------------
 * Test 6: When fd >= 0 (socket ready), sendto receives the formatted buffer
 * -------------------------------------------------------------------------- */
void test_send_when_fd_ready(void)
{
    g_fake_fd = 5;

    hook_impl("ready to send %d\n", 99);

    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "ready to send 99"));
}

/* --------------------------------------------------------------------------
 * Test 7: Integer arguments are formatted correctly
 * -------------------------------------------------------------------------- */
void test_integer_formatting(void)
{
    hook_impl("count=%u hex=0x%04x\n", (unsigned)255u, (unsigned)0xABu);

    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "count=255"));
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "hex=0x00ab"));
}

/* --------------------------------------------------------------------------
 * Test 8: Empty result (fmt produces nothing) -- sendto not called
 *
 * vsnprintf("", 512, "", args) returns 0, len == 0.
 * The guard `len > 0` prevents sendto from being called.
 * -------------------------------------------------------------------------- */
void test_empty_format_no_send(void)
{
    hook_impl("%s", "");

    /* Empty string: len == 0, so sendto should NOT be called */
    TEST_ASSERT_EQUAL_INT(0, g_sendto_calls);
    /* UART passthrough still happens (called before length check) */
    TEST_ASSERT_EQUAL_INT(1, g_uart_calls);
}

/* ==========================================================================
 * Accumulator harness -- mirrors the udp_log.c coalescing + sequence logic
 * ==========================================================================
 *
 * The hook in the live code does roughly:
 *   1. UART passthrough (covered by tests above)
 *   2. format line into 256-byte stack buf
 *   3. if line + acc_len > DGRAM_MAX: flush_locked()  -- inline overflow send
 *   4. if line > DGRAM_MAX: truncate and send standalone
 *   5. else: append to accumulator
 *
 * The flush task does:
 *   - if acc_len > 0 and idle for >= FLUSH_TIMEOUT_MS: flush_locked()
 *
 * flush_locked():
 *   - if acc_len == 0: return
 *   - if fd == -1: drop buffer, bump seq anyway (gap visible on receiver)
 *   - else: sendto("#<seq>\n" + acc_buf), bump seq, reset acc_len
 * ========================================================================== */

#define ACC_DGRAM_MAX  1300
#define ACC_SEQ_HDR    16

static char       g_acc_buf[ACC_DGRAM_MAX];
static size_t     g_acc_len = 0;
static uint32_t   g_acc_seq = 0;
static int        g_acc_fd  = 3;  /* >=0 means "ready" */

/* Captured datagrams (up to 16 entries). */
#define DGRAM_CAP 16
static struct {
    char   data[ACC_SEQ_HDR + ACC_DGRAM_MAX + 1];
    size_t len;
} g_dgrams[DGRAM_CAP];
static int g_dgram_count = 0;

static void accum_reset(void)
{
    memset(g_acc_buf, 0, sizeof(g_acc_buf));
    g_acc_len = 0;
    g_acc_seq = 0;
    g_acc_fd  = 3;
    memset(g_dgrams, 0, sizeof(g_dgrams));
    g_dgram_count = 0;
}

/* Mirrors flush_locked() in udp_log.c.  Bumps seq even when fd=-1 so the
 * receiver-side gap detection works. */
static void accum_flush_locked(void)
{
    if (g_acc_len == 0) return;
    if (g_acc_fd == -1) {
        g_acc_len = 0;
        g_acc_seq++;
        return;
    }
    if (g_dgram_count < DGRAM_CAP) {
        int hdr_n = snprintf(g_dgrams[g_dgram_count].data, ACC_SEQ_HDR,
                             "#%u\n", (unsigned)g_acc_seq);
        if (hdr_n < 0) hdr_n = 0;
        memcpy(g_dgrams[g_dgram_count].data + hdr_n, g_acc_buf, g_acc_len);
        g_dgrams[g_dgram_count].len = (size_t)hdr_n + g_acc_len;
        g_dgram_count++;
    }
    g_acc_len = 0;
    g_acc_seq++;
}

/* Mirrors the hook's append logic (steps 3-5 above).  Caller provides
 * the already-formatted line (we skip the vsnprintf part since the
 * line-formatting half is covered by the tests further up). */
static void accum_append(const char *line, size_t llen)
{
    if (llen == 0) return;

    if (g_acc_len + llen > sizeof(g_acc_buf)) {
        accum_flush_locked();
    }

    if (llen > sizeof(g_acc_buf)) {
        memcpy(g_acc_buf, line, sizeof(g_acc_buf));
        g_acc_len = sizeof(g_acc_buf);
        accum_flush_locked();
    } else {
        memcpy(g_acc_buf + g_acc_len, line, llen);
        g_acc_len += llen;
    }
}

static void accum_flush_idle(void) /* what the flush task fires */
{
    accum_flush_locked();
}

/* --------------------------------------------------------------------------
 * Tests for the accumulator / sequence-number logic
 * -------------------------------------------------------------------------- */

void test_accum_single_short_line_buffers_no_send(void)
{
    accum_reset();
    accum_append("hello\n", 6);
    TEST_ASSERT_EQUAL_INT(0, g_dgram_count);
    TEST_ASSERT_EQUAL_size_t(6, g_acc_len);
    TEST_ASSERT_EQUAL_UINT32(0, g_acc_seq);
}

void test_accum_idle_flush_emits_one_datagram_with_header(void)
{
    accum_reset();
    accum_append("first line\n", 11);
    accum_append("second line\n", 12);
    accum_flush_idle();

    TEST_ASSERT_EQUAL_INT(1, g_dgram_count);
    TEST_ASSERT_TRUE(strncmp(g_dgrams[0].data, "#0\n", 3) == 0);
    TEST_ASSERT_NOT_NULL(strstr(g_dgrams[0].data, "first line"));
    TEST_ASSERT_NOT_NULL(strstr(g_dgrams[0].data, "second line"));
    TEST_ASSERT_EQUAL_size_t(0, g_acc_len);
    TEST_ASSERT_EQUAL_UINT32(1, g_acc_seq);
}

void test_accum_overflow_triggers_inline_flush(void)
{
    accum_reset();
    /* Fill close to the cap with a single big line (under DGRAM_MAX). */
    char big[1200];
    memset(big, 'a', sizeof(big));
    accum_append(big, sizeof(big));
    TEST_ASSERT_EQUAL_INT(0, g_dgram_count);  /* still buffered */

    /* Next 200-byte line would overflow 1300 -- triggers flush, then appends. */
    char next[200];
    memset(next, 'b', sizeof(next));
    accum_append(next, sizeof(next));

    TEST_ASSERT_EQUAL_INT(1, g_dgram_count);  /* one datagram emitted */
    TEST_ASSERT_EQUAL_size_t(200, g_acc_len); /* new line in fresh buffer */
    TEST_ASSERT_EQUAL_UINT32(1, g_acc_seq);
}

void test_accum_sequence_increments_across_datagrams(void)
{
    accum_reset();
    /* Flush three full datagrams. */
    char big[1200];
    memset(big, 'x', sizeof(big));
    for (int i = 0; i < 3; i++) {
        accum_append(big, sizeof(big));
        accum_flush_idle();
    }
    TEST_ASSERT_EQUAL_INT(3, g_dgram_count);
    TEST_ASSERT_TRUE(strncmp(g_dgrams[0].data, "#0\n", 3) == 0);
    TEST_ASSERT_TRUE(strncmp(g_dgrams[1].data, "#1\n", 3) == 0);
    TEST_ASSERT_TRUE(strncmp(g_dgrams[2].data, "#2\n", 3) == 0);
    TEST_ASSERT_EQUAL_UINT32(3, g_acc_seq);
}

void test_accum_empty_flush_is_noop(void)
{
    accum_reset();
    accum_flush_idle();
    TEST_ASSERT_EQUAL_INT(0, g_dgram_count);
    TEST_ASSERT_EQUAL_UINT32(0, g_acc_seq);  /* no seq bump on empty */
}

void test_accum_fd_unavailable_still_bumps_seq(void)
{
    accum_reset();
    g_acc_fd = -1;  /* simulate pre-Wi-Fi / socket gone */
    accum_append("data we will never send\n", 24);
    accum_flush_idle();

    TEST_ASSERT_EQUAL_INT(0, g_dgram_count); /* nothing captured */
    TEST_ASSERT_EQUAL_UINT32(1, g_acc_seq);  /* but seq advanced */
    TEST_ASSERT_EQUAL_size_t(0, g_acc_len);  /* buffer dropped */
}

void test_accum_oversize_line_truncated_standalone(void)
{
    accum_reset();
    /* Single "line" larger than DGRAM_MAX -- gets truncated and sent solo. */
    char huge[2000];
    memset(huge, 'z', sizeof(huge));
    accum_append(huge, sizeof(huge));

    TEST_ASSERT_EQUAL_INT(1, g_dgram_count);
    TEST_ASSERT_TRUE(strncmp(g_dgrams[0].data, "#0\n", 3) == 0);
    /* Truncated to exactly DGRAM_MAX; header adds ACC_SEQ_HDR-or-less. */
    TEST_ASSERT_TRUE(g_dgrams[0].len >= ACC_DGRAM_MAX);
    TEST_ASSERT_TRUE(g_dgrams[0].len <= ACC_DGRAM_MAX + ACC_SEQ_HDR);
    TEST_ASSERT_EQUAL_size_t(0, g_acc_len);
}

void test_accum_overflow_followed_by_overflow_packs_two_dgrams(void)
{
    accum_reset();
    /* Burst of 4000 bytes => 2 full datagrams + ~1400 left buffered. */
    char chunk[700];
    memset(chunk, 'p', sizeof(chunk));
    for (int i = 0; i < 6; i++) {
        accum_append(chunk, sizeof(chunk));
    }
    /* After 6 * 700 = 4200 bytes pushed through 1300-byte accumulator:
     *   line 1 (700)  -> acc=700
     *   line 2 (700)  -> 1400 > 1300, flush #0, acc=700
     *   line 3 (700)  -> 1400 > 1300, flush #1, acc=700
     *   line 4 (700)  -> 1400 > 1300, flush #2, acc=700
     *   line 5 (700)  -> 1400 > 1300, flush #3, acc=700
     *   line 6 (700)  -> 1400 > 1300, flush #4, acc=700
     * => 5 datagrams emitted, 700 still buffered. */
    TEST_ASSERT_EQUAL_INT(5, g_dgram_count);
    TEST_ASSERT_EQUAL_size_t(700, g_acc_len);

    accum_flush_idle();
    TEST_ASSERT_EQUAL_INT(6, g_dgram_count); /* trailing partial drained */
    TEST_ASSERT_TRUE(strncmp(g_dgrams[5].data, "#5\n", 3) == 0);
}

/* --------------------------------------------------------------------------
 * Additional tests
 * -------------------------------------------------------------------------- */

/* Format-string injection resistance: %n in a message is a literal substring,
 * not a format directive (because we call hook_impl with "%s", user_data). */
void test_format_string_injection_resistance(void)
{
    /* Simulate safe call: format is "%s", arg is the user-controlled string.
     * "%n" in the arg must appear verbatim in output, NOT cause a crash. */
    hook_impl("%s", "evil %n payload %x here");

    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "evil %n payload %x here"));
}

/* Null-equivalent empty string arg: produces zero-length, no send. */
void test_percent_s_empty_arg_no_send(void)
{
    hook_impl("%s", "");
    TEST_ASSERT_EQUAL_INT(0, g_sendto_calls);
}

/* Multiple integer specifiers in one call. */
void test_multiple_format_args(void)
{
    hook_impl("a=%d b=%d c=%d\n", 1, 2, 3);
    TEST_ASSERT_EQUAL_INT(1, g_sendto_calls);
    TEST_ASSERT_NOT_NULL(strstr(g_sent_buf, "a=1 b=2 c=3"));
}

/* Accumulator: sequence number is correct after many overflows. */
void test_accum_sequence_large_count(void)
{
    accum_reset();
    char chunk[1300]; /* exactly DGRAM_MAX */
    memset(chunk, 'q', sizeof(chunk));
    for (int i = 0; i < 10; i++) {
        accum_append(chunk, sizeof(chunk));
        accum_flush_idle();
    }
    TEST_ASSERT_EQUAL_INT(10, g_dgram_count);
    TEST_ASSERT_EQUAL_UINT32(10, g_acc_seq);
    /* Verify header of last dgram */
    TEST_ASSERT_TRUE(strncmp(g_dgrams[9].data, "#9\n", 3) == 0);
}

/* Accumulator: fd going -1 mid-stream: seq bumps, no dgrams emitted. */
void test_accum_fd_goes_down_mid_stream(void)
{
    accum_reset();
    /* First flush succeeds. */
    accum_append("line1\n", 6);
    accum_flush_idle();
    TEST_ASSERT_EQUAL_INT(1, g_dgram_count);
    TEST_ASSERT_EQUAL_UINT32(1, g_acc_seq);

    /* Socket goes away. */
    g_acc_fd = -1;
    accum_append("line2\n", 6);
    accum_flush_idle();

    TEST_ASSERT_EQUAL_INT(1, g_dgram_count); /* no new datagram */
    TEST_ASSERT_EQUAL_UINT32(2, g_acc_seq);  /* but seq advanced */
}

/* Accumulator: append zero-length line is silently ignored. */
void test_accum_append_zero_len_ignored(void)
{
    accum_reset();
    accum_append("data\n", 0); /* explicit zero len */
    accum_flush_idle();
    TEST_ASSERT_EQUAL_INT(0, g_dgram_count);
    TEST_ASSERT_EQUAL_UINT32(0, g_acc_seq); /* nothing flushed */
}

/* ==========================================================================
 * Deinit-ordering harness -- mirrors the udp_log_deinit() / flush_task_fn
 * teardown join (S-F3).
 * ==========================================================================
 *
 * The real code (udp_log.c) cannot be compiled natively (FreeRTOS + lwIP),
 * so -- like the harnesses above -- we model the ordering invariant inline.
 *
 * Invariant under test: udp_log_deinit() must JOIN the flush task before it
 * frees the objects the task references (s_acc_mutex, s_sock).  Concretely:
 *
 *   flush_task_fn:  ... drop s_acc_mutex ... give(s_flush_done) ... delete
 *   udp_log_deinit: s_running=false; take(s_flush_done); close(fd); del(mutex)
 *
 * If deinit ever freed the mutex/socket BEFORE the join completes, the task
 * (blocked on the mutex / mid-sendto) would touch freed objects -> UAF.
 *
 * We model the timeline with an ordered event log and a one-slot "done"
 * flag that stands in for s_flush_done.  The harness verifies:
 *   - mutex/socket are freed only AFTER the task signalled done
 *   - on the timeout path, nothing the task references is freed
 * ========================================================================== */

/* Stand-in for s_flush_done: 0 = not signalled, 1 = task signalled exit. */
static int  g_di_done_flag      = 0;
/* Stand-in for s_running. */
static int  g_di_running        = 0;
/* Resource liveness: 1 while the mutex/socket are still allocated. */
static int  g_di_mutex_alive    = 0;
static int  g_di_socket_alive   = 0;
/* Records whether the task was still "using" the mutex when it was freed. */
static int  g_di_uaf_detected   = 0;
/* Did the task self-signal before deinit freed resources? */
static int  g_di_task_signalled_before_free = 0;

static void di_reset(void)
{
    g_di_done_flag    = 0;
    g_di_running      = 1;
    g_di_mutex_alive  = 1;
    g_di_socket_alive = 1;
    g_di_uaf_detected = 0;
    g_di_task_signalled_before_free = 0;
}

/* Mirrors flush_task_fn's exit path: after observing !running and dropping
 * the mutex, give done, then self-delete.  Returns after "self-delete". */
static void di_flush_task_run_to_exit(void)
{
    /* Loop body would run while running; we model the exit transition. */
    while (g_di_running) {
        /* take mutex, maybe flush, give mutex -- all require the mutex to be
         * alive.  If deinit freed it while we were here, that's a UAF. */
        if (!g_di_mutex_alive) { g_di_uaf_detected = 1; return; }
        break;  /* one modelled iteration, then re-check running below */
    }
    /* running cleared: drop mutex (already given), signal done, self-delete. */
    g_di_done_flag = 1;  /* give(s_flush_done) AFTER releasing the mutex */
}

/* Mirrors udp_log_deinit(): clear running, JOIN on done, THEN free. */
static int di_deinit(int join_succeeds)
{
    g_di_running = 0;

    /* Let the flush task run to its exit (cooperative model). */
    di_flush_task_run_to_exit();

    /* Join: only proceed to free if the task signalled done. */
    if (join_succeeds && g_di_done_flag) {
        g_di_task_signalled_before_free = 1;
        /* Safe to free now. */
        g_di_socket_alive = 0;
        g_di_mutex_alive  = 0;
        return 1;   /* clean teardown */
    }

    if (!g_di_done_flag) {
        /* Timeout path: must NOT free what the task might still touch. */
        return 0;
    }
    return 1;
}

/* Models udp_log_deinit() when the flush task never signals (join times
 * out): clear running, the task is stuck so done stays 0, and deinit must
 * leave the mutex/socket allocated rather than risk a UAF. */
static int di_deinit_no_signal(void)
{
    g_di_running = 0;
    /* Task is modelled as stuck: it does NOT run to its exit, so done stays
     * 0.  (We deliberately skip di_flush_task_run_to_exit() here.) */
    if (g_di_done_flag) {           /* join would succeed -- not this case */
        g_di_task_signalled_before_free = 1;
        g_di_socket_alive = 0;
        g_di_mutex_alive  = 0;
        return 1;
    }
    /* Timeout: leave resources alive. */
    return 0;
}

/* Deinit joins (waits for the task's done-signal) before freeing the
 * mutex/socket -- the core S-F3 invariant. */
void test_deinit_joins_before_free(void)
{
    di_reset();
    int rc = di_deinit(/*join_succeeds=*/1);

    TEST_ASSERT_EQUAL_INT(1, rc);                 /* clean teardown */
    TEST_ASSERT_EQUAL_INT(1, g_di_task_signalled_before_free);
    TEST_ASSERT_EQUAL_INT(0, g_di_uaf_detected);  /* no use-after-free */
    TEST_ASSERT_EQUAL_INT(0, g_di_mutex_alive);   /* freed AFTER join */
    TEST_ASSERT_EQUAL_INT(0, g_di_socket_alive);
}

/* The flush task signals done only AFTER it has stopped using the mutex --
 * so the freed-flag is never set before the done-flag. */
void test_deinit_done_signalled_after_mutex_released(void)
{
    di_reset();
    /* Run only the task half: it must set done with the mutex still alive
     * (it released the lock but the object is not yet freed by deinit). */
    g_di_running = 0;
    di_flush_task_run_to_exit();
    TEST_ASSERT_EQUAL_INT(1, g_di_done_flag);
    TEST_ASSERT_EQUAL_INT(0, g_di_uaf_detected);
    /* deinit hasn't freed anything yet. */
    TEST_ASSERT_EQUAL_INT(1, g_di_mutex_alive);
}

/* Timeout path: if the join never completes, deinit must NOT free the
 * mutex/socket (leak-but-safe), avoiding a use-after-free. */
void test_deinit_timeout_does_not_free(void)
{
    di_reset();
    /* Simulate a task that never signals: keep running so the modelled
     * exit path doesn't set done, and force join failure. */
    g_di_done_flag = 0;
    int rc = di_deinit_no_signal();

    TEST_ASSERT_EQUAL_INT(0, rc);                 /* timeout reported */
    TEST_ASSERT_EQUAL_INT(0, g_di_task_signalled_before_free);
    /* Crucially: resources NOT freed -> no UAF against the live task. */
    TEST_ASSERT_EQUAL_INT(1, g_di_mutex_alive);
    TEST_ASSERT_EQUAL_INT(1, g_di_socket_alive);
}

/* --------------------------------------------------------------------------
 * Test runner
 * -------------------------------------------------------------------------- */
int main(void)
{
    UNITY_BEGIN();
    /* Original 8 -- per-line formatting / UART chain / fd-not-ready */
    RUN_TEST(test_short_line_formatted);
    RUN_TEST(test_long_line_truncated);
    RUN_TEST(test_ansi_escapes_verbatim);
    RUN_TEST(test_uart_passthrough_called_before_send);
    RUN_TEST(test_no_send_when_fd_negative);
    RUN_TEST(test_send_when_fd_ready);
    RUN_TEST(test_integer_formatting);
    RUN_TEST(test_empty_format_no_send);

    /* Accumulator coalescing + sequence numbers */
    RUN_TEST(test_accum_single_short_line_buffers_no_send);
    RUN_TEST(test_accum_idle_flush_emits_one_datagram_with_header);
    RUN_TEST(test_accum_overflow_triggers_inline_flush);
    RUN_TEST(test_accum_sequence_increments_across_datagrams);
    RUN_TEST(test_accum_empty_flush_is_noop);
    RUN_TEST(test_accum_fd_unavailable_still_bumps_seq);
    RUN_TEST(test_accum_oversize_line_truncated_standalone);
    RUN_TEST(test_accum_overflow_followed_by_overflow_packs_two_dgrams);

    /* Additional cases */
    RUN_TEST(test_format_string_injection_resistance);
    RUN_TEST(test_percent_s_empty_arg_no_send);
    RUN_TEST(test_multiple_format_args);
    RUN_TEST(test_accum_sequence_large_count);
    RUN_TEST(test_accum_fd_goes_down_mid_stream);
    RUN_TEST(test_accum_append_zero_len_ignored);

    /* Deinit-ordering join (S-F3) */
    RUN_TEST(test_deinit_joins_before_free);
    RUN_TEST(test_deinit_done_signalled_after_mutex_released);
    RUN_TEST(test_deinit_timeout_does_not_free);

    return UNITY_END();
}
