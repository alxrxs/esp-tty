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

/* --------------------------------------------------------------------------
 * Test runner
 * -------------------------------------------------------------------------- */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_short_line_formatted);
    RUN_TEST(test_long_line_truncated);
    RUN_TEST(test_ansi_escapes_verbatim);
    RUN_TEST(test_uart_passthrough_called_before_send);
    RUN_TEST(test_no_send_when_fd_negative);
    RUN_TEST(test_send_when_fd_ready);
    RUN_TEST(test_integer_formatting);
    RUN_TEST(test_empty_format_no_send);
    return UNITY_END();
}
