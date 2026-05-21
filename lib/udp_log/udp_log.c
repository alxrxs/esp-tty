/*
 * udp_log.c -- UDP log mirror implementation
 *
 * Only compiled when both UDP_LOG_HOST and UDP_LOG_PORT are defined.
 *
 * Design notes:
 *
 *   vprintf hook:
 *     esp_log_set_vprintf() lets us intercept every ESP_LOG* call.  The
 *     hook calls the previous vprintf first (keeping UART0 output intact),
 *     then formats the message into a ~512-byte stack buffer (truncating
 *     longer lines) and sends it as a single UDP datagram.
 *
 *   No mutex inside the hook:
 *     ESP_LOG* can be called from any context including ISRs.  Taking a
 *     blocking mutex in the hook would risk deadlock.  The socket fd is
 *     published via an atomic store; lazy init uses a trylock and skips
 *     UDP send if init is already in progress on another context.
 *
 *   No dynamic allocation per log line:
 *     All per-call buffers are on the stack.  Lazy init allocates the
 *     socket once; that happens outside the hot path.
 *
 *   Lazy socket creation:
 *     The UDP socket is created on the first log call after udp_log_init()
 *     installs the hook.  lwIP's socket layer is guaranteed ready by then
 *     (we are already past the Wi-Fi GOT_IP event).
 *
 *   ANSI escape sequences:
 *     ESP-IDF colours log output with ANSI escape codes.  We send them
 *     as-is; any ANSI-capable terminal renders them correctly.  Strip with
 *     `sed 's/\x1B\[[0-9;]*m//g'` if you prefer plain text.
 *
 *   Wi-Fi guard:
 *     If Wi-Fi is not yet associated, sendto() fails with ENETUNREACH or
 *     similar.  We silently drop the datagram to avoid infinite recursion
 *     (logging the error would re-enter the hook).
 */

#include "udp_log.h"

#if defined(UDP_LOG_HOST) && defined(UDP_LOG_PORT)

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/* Line buffer size.  Lines longer than this are truncated at
 * UDP_LOG_BUF_SIZE - 1 bytes before the NUL terminator. */
#ifndef UDP_LOG_BUF_SIZE
# define UDP_LOG_BUF_SIZE  512
#endif

/* --------------------------------------------------------------------------
 * Module state
 * -------------------------------------------------------------------------- */

/* Previously installed vprintf handler (restored by udp_log_deinit). */
static vprintf_like_t s_prev_vprintf = NULL;

/* UDP socket fd.  -1 = not yet created.
 * Written once under s_init_mutex, then read-only from the hook. */
static atomic_int s_sock = ATOMIC_VAR_INIT(-1);

/* Destination address, populated once during lazy init. */
static struct sockaddr_in s_dest;

/* Mutex protecting lazy socket creation.  Never taken inside the vprintf
 * hook to avoid blocking callers from interrupt context (see design notes). */
static SemaphoreHandle_t s_init_mutex = NULL;

/* True after udp_log_init() installs the hook. */
static volatile bool s_installed = false;

/* --------------------------------------------------------------------------
 * Lazy socket creation
 *
 * Called from the vprintf hook the first time it fires.  Any failure
 * leaves s_sock at -1 so subsequent calls silently skip the UDP send.
 * -------------------------------------------------------------------------- */
static void udp_lazy_init(void)
{
    if (!s_init_mutex) return;

    /* Non-blocking trylock: if another context is already in here, skip
     * init this time.  The hook will retry on the next log line. */
    if (xSemaphoreTake(s_init_mutex, 0) != pdTRUE) return;

    /* Double-check after acquiring the lock. */
    if (atomic_load(&s_sock) != -1) {
        xSemaphoreGive(s_init_mutex);
        return;
    }

    /* Create a non-blocking UDP socket. */
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        xSemaphoreGive(s_init_mutex);
        return;
    }

    /* Resolve destination address (IPv4 only, dotted-decimal string). */
    memset(&s_dest, 0, sizeof(s_dest));
    s_dest.sin_family = AF_INET;
    s_dest.sin_port   = htons((uint16_t)(UDP_LOG_PORT));
    if (inet_pton(AF_INET, UDP_LOG_HOST, &s_dest.sin_addr) != 1) {
        close(fd);
        xSemaphoreGive(s_init_mutex);
        return;
    }

    /* Make the socket non-blocking so sendto() never stalls the log caller. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    /* Publish the fd atomically so the hook sees it immediately. */
    atomic_store(&s_sock, fd);

    xSemaphoreGive(s_init_mutex);
}

/* --------------------------------------------------------------------------
 * vprintf hook
 * -------------------------------------------------------------------------- */
static int udp_log_vprintf_hook(const char *fmt, va_list args)
{
    /* 1. Call the previous vprintf FIRST so UART0 output is never gated on
     *    network availability.  Use a copy of args; the original is needed
     *    for vsnprintf below. */
    int ret = 0;
    if (s_prev_vprintf) {
        va_list args_uart;
        va_copy(args_uart, args);
        ret = s_prev_vprintf(fmt, args_uart);
        va_end(args_uart);
    }

    /* 2. Format into a stack buffer for UDP.  Truncates at BUF_SIZE - 1. */
    char buf[UDP_LOG_BUF_SIZE];
    int  n = vsnprintf(buf, sizeof(buf), fmt, args);
    if (n < 0) n = 0;
    size_t len = ((size_t)n < sizeof(buf)) ? (size_t)n : sizeof(buf) - 1;

    /* 3. Lazy-init the socket (no-op after first successful creation). */
    int fd = atomic_load(&s_sock);
    if (fd == -1) {
        udp_lazy_init();
        fd = atomic_load(&s_sock);
    }

    /* 4. Best-effort UDP send.  Silently drop on any error (ENETUNREACH
     *    before Wi-Fi is up, EAGAIN if the TX buffer is full, etc.). */
    if (fd != -1 && len > 0) {
        sendto(fd, buf, len, 0,
               (struct sockaddr *)&s_dest, sizeof(s_dest));
    }

    return ret;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

esp_err_t udp_log_init(void)
{
    if (s_installed) return ESP_OK;

    s_init_mutex = xSemaphoreCreateMutex();
    if (!s_init_mutex) {
        return ESP_FAIL;
    }

    /* Install the hook; save the previous handler for UART passthrough. */
    s_prev_vprintf = esp_log_set_vprintf(udp_log_vprintf_hook);
    s_installed    = true;
    return ESP_OK;
}

void udp_log_deinit(void)
{
    if (!s_installed) return;

    /* Restore the previous handler. */
    esp_log_set_vprintf(s_prev_vprintf);
    s_prev_vprintf = NULL;
    s_installed    = false;

    /* Close the socket. */
    int fd = atomic_exchange(&s_sock, -1);
    if (fd >= 0) {
        close(fd);
    }

    if (s_init_mutex) {
        vSemaphoreDelete(s_init_mutex);
        s_init_mutex = NULL;
    }
}

#endif /* UDP_LOG_HOST && UDP_LOG_PORT */
