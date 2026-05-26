/*
 * udp_log.c -- UDP log mirror with coalescing + sequence numbers
 *
 * Only compiled when both UDP_LOG_HOST and UDP_LOG_PORT are defined.
 *
 * Design
 * ------
 *
 *   vprintf hook
 *     esp_log_set_vprintf() lets us intercept every ESP_LOG* call.  The hook
 *     calls the previous vprintf first (UART0 passthrough), then appends the
 *     formatted line to a single-datagram accumulator.
 *
 *   Coalescing
 *     Per-line UDP send hit a per-second packet-rate ceiling during boot
 *     bursts -- some lines were lost between the chip and the kernel.  We
 *     buffer up to UDP_LOG_DGRAM_MAX bytes (default 1300, near a path MTU)
 *     and emit one datagram either when the buffer is about to overflow OR
 *     when a background task sees the buffer has been idle for
 *     UDP_LOG_FLUSH_TIMEOUT_MS.
 *
 *   Sequence numbers
 *     Each datagram is prefixed with "#<seq>\n".  Gaps in the sequence on
 *     the receiver mean datagrams were lost in transit (Wi-Fi flap, kernel
 *     queue overflow, etc.) -- you know to scroll the UART log for what is
 *     missing.
 *
 *   Locking
 *     A single mutex guards the accumulator.  The hook uses trylock and
 *     drops the current line on contention (rare; only collides with the
 *     flush task during its brief drain).  The flush task uses blocking
 *     acquire.  No mutex is taken from ISR context -- ESP_LOG from an ISR
 *     would skip via the trylock.
 *
 *   Non-blocking send
 *     The socket is O_NONBLOCK; sendto() returns instantly even when the
 *     LwIP TX queue is full (drops on EAGAIN, same as UDP overflow).
 */

/* Pull in UDP_LOG_HOST / UDP_LOG_PORT before the guard below; udp_log.h
 * doesn't include config.h so the .c would otherwise compile as empty. */
#include "config.h"
#include "udp_log.h"

#if defined(UDP_LOG_HOST) && defined(UDP_LOG_PORT)

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

/* --------------------------------------------------------------------------
 * Tunables (override in config.h if needed)
 * -------------------------------------------------------------------------- */

/* Per-line scratch buffer.  A single ESP_LOG line longer than this is
 * truncated.  Stays on the stack inside the vprintf hook. */
#ifndef UDP_LOG_LINE_MAX
# define UDP_LOG_LINE_MAX  256
#endif

/* Datagram payload ceiling.  1300 leaves room for the IPv4+UDP header
 * (28 B) and any tunnel overhead under a typical 1500-byte path MTU. */
#ifndef UDP_LOG_DGRAM_MAX
# define UDP_LOG_DGRAM_MAX  1300
#endif

/* Sequence-number header buffer ("#4294967295\n" = 12 chars + slack). */
#define UDP_LOG_SEQ_HDR_MAX  16

/* If the accumulator has been idle for this many ms with content in it,
 * the flush task emits it as a datagram. */
#ifndef UDP_LOG_FLUSH_TIMEOUT_MS
# define UDP_LOG_FLUSH_TIMEOUT_MS  50
#endif

/* How often the flush task wakes to check the idle-timeout condition.
 * Lower = more responsive, higher = less CPU wake.  25 ms is a good
 * compromise for debug logging. */
#ifndef UDP_LOG_POLL_MS
# define UDP_LOG_POLL_MS  25
#endif

/* Flush task stack.  Holds the wire-stitch buffer (~1.3 KB) plus FreeRTOS
 * bookkeeping; 4 KB is comfortable. */
#ifndef UDP_LOG_FLUSH_STACK
# define UDP_LOG_FLUSH_STACK  4096
#endif

/* Flush task priority.  Low so it never preempts real work. */
#ifndef UDP_LOG_FLUSH_PRIO
# define UDP_LOG_FLUSH_PRIO  3
#endif

/* --------------------------------------------------------------------------
 * Module state
 * -------------------------------------------------------------------------- */

/* Previously installed vprintf handler (restored by udp_log_deinit). */
static vprintf_like_t s_prev_vprintf = NULL;

/* UDP socket fd.  -1 = not yet created. */
static atomic_int s_sock = ATOMIC_VAR_INIT(-1);

/* Destination address, populated once during lazy init. */
static struct sockaddr_in s_dest;

/* Lazy-init mutex -- separate from the accumulator mutex so socket
 * creation does not block log callsites. */
static SemaphoreHandle_t s_init_mutex = NULL;

/* Accumulator buffer + length.  Guarded by s_acc_mutex. */
static char             s_acc_buf[UDP_LOG_DGRAM_MAX];
static size_t           s_acc_len   = 0;
static TickType_t       s_acc_last_add = 0;
static uint32_t         s_seq       = 0;
static SemaphoreHandle_t s_acc_mutex = NULL;

/* Wire-stitch buffer used by flush_locked().  Accessed only while holding
 * s_acc_mutex, so a single static instance is safe. */
static char s_wire[UDP_LOG_SEQ_HDR_MAX + UDP_LOG_DGRAM_MAX];

/* Flush task handle + running flag. */
static TaskHandle_t s_flush_task = NULL;
static volatile bool s_running   = false;

/* True after udp_log_init() installs the hook. */
static volatile bool s_installed = false;

/* --------------------------------------------------------------------------
 * Lazy socket creation
 * -------------------------------------------------------------------------- */
static void udp_lazy_init(void)
{
    if (!s_init_mutex) return;
    /* Use a blocking take so that when two threads race to initialise, the
     * loser waits and then observes the already-set socket rather than
     * silently skipping init (the previous trylock with timeout=0 behaviour). */
    if (xSemaphoreTake(s_init_mutex, portMAX_DELAY) != pdTRUE) return;

    if (atomic_load(&s_sock) != -1) {
        xSemaphoreGive(s_init_mutex);
        return;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        xSemaphoreGive(s_init_mutex);
        return;
    }

    memset(&s_dest, 0, sizeof(s_dest));
    s_dest.sin_family = AF_INET;
    s_dest.sin_port   = htons((uint16_t)(UDP_LOG_PORT));

    /* Try inet_pton first (dotted-decimal IP literal).  If that fails, fall
     * back to getaddrinfo so that hostnames are also accepted.  On failure
     * log once, set s_sock to -1 (already -1 here), and disable future
     * attempts by leaving s_sock = -1. */
    if (inet_pton(AF_INET, UDP_LOG_HOST, &s_dest.sin_addr) != 1) {
        struct addrinfo hints;
        struct addrinfo *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(UDP_LOG_HOST, NULL, &hints, &res) == 0 && res) {
            s_dest.sin_addr =
                ((struct sockaddr_in *)res->ai_addr)->sin_addr;
            freeaddrinfo(res);
        } else {
            if (res) freeaddrinfo(res);
            ESP_LOGE("udp_log",
                     "udp_lazy_init: cannot resolve UDP_LOG_HOST=\"%s\"; "
                     "UDP logging disabled",
                     UDP_LOG_HOST);
            close(fd);
            /* Leave s_sock at -1; stop all future log attempts. */
            xSemaphoreGive(s_init_mutex);
            return;
        }
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    atomic_store(&s_sock, fd);
    xSemaphoreGive(s_init_mutex);
}

/* --------------------------------------------------------------------------
 * Flush -- emit the current accumulator as one datagram, with sequence
 * header.  Caller must hold s_acc_mutex.
 * -------------------------------------------------------------------------- */
static void flush_locked(void)
{
    if (s_acc_len == 0) return;

    int fd = atomic_load(&s_sock);
    if (fd == -1) {
        /* Network not ready -- drop the accumulator rather than buffer
         * unboundedly.  The sequence number still advances so the receiver
         * sees the gap. */
        s_acc_len = 0;
        s_seq++;
        return;
    }

    /* "#<seq>\n" prefix.  Capped at UDP_LOG_SEQ_HDR_MAX - 1 so the header
     * never overstates its length: snprintf writes at most SEQ_HDR_MAX bytes
     * including the NUL, so the usable payload is at most SEQ_HDR_MAX - 1
     * bytes.  Clamping to SEQ_HDR_MAX (without -1) would corrupt the wire
     * format by claiming one extra byte that is actually the NUL terminator. */
    int hdr_n = snprintf(s_wire, UDP_LOG_SEQ_HDR_MAX, "#%u\n",
                         (unsigned)s_seq);
    if (hdr_n < 0) hdr_n = 0;
    if (hdr_n > UDP_LOG_SEQ_HDR_MAX - 1) hdr_n = UDP_LOG_SEQ_HDR_MAX - 1;

    memcpy(s_wire + hdr_n, s_acc_buf, s_acc_len);
    size_t total = (size_t)hdr_n + s_acc_len;

    sendto(fd, s_wire, total, 0,
           (struct sockaddr *)&s_dest, sizeof(s_dest));

    s_acc_len = 0;
    s_seq++;
}

/* --------------------------------------------------------------------------
 * vprintf hook
 * -------------------------------------------------------------------------- */
static int udp_log_vprintf_hook(const char *fmt, va_list args)
{
    /* 1. UART0 passthrough -- always, even if UDP is gated. */
    int ret = 0;
    if (s_prev_vprintf) {
        va_list args_uart;
        va_copy(args_uart, args);
        ret = s_prev_vprintf(fmt, args_uart);
        va_end(args_uart);
    }

    /* 2. Format into a per-call stack buffer. */
    char line[UDP_LOG_LINE_MAX];
    int n = vsnprintf(line, sizeof(line), fmt, args);
    if (n < 0) n = 0;
    size_t llen = ((size_t)n < sizeof(line)) ? (size_t)n : sizeof(line) - 1;
    if (llen == 0) return ret;

    /* 3. Lazy socket creation on first use. */
    if (atomic_load(&s_sock) == -1) {
        udp_lazy_init();
        if (atomic_load(&s_sock) == -1) return ret;
    }

    if (!s_acc_mutex) return ret;

    /* 4. Trylock the accumulator.  Contention is rare (only against the
     *    flush task during its drain), and dropping a line on contention
     *    is preferable to ever blocking a logging callsite. */
    if (xSemaphoreTake(s_acc_mutex, 0) != pdTRUE) return ret;

    /* If this line would overflow the accumulator, flush first. */
    if (s_acc_len + llen > sizeof(s_acc_buf)) {
        flush_locked();
    }

    /* If a single line is bigger than the entire datagram, send it
     * standalone (truncated).  This is a degenerate case -- long lines
     * are rare and capped by UDP_LOG_LINE_MAX anyway. */
    if (llen > sizeof(s_acc_buf)) {
        memcpy(s_acc_buf, line, sizeof(s_acc_buf));
        s_acc_len = sizeof(s_acc_buf);
        flush_locked();
    } else {
        memcpy(s_acc_buf + s_acc_len, line, llen);
        s_acc_len += llen;
        s_acc_last_add = xTaskGetTickCount();
    }

    xSemaphoreGive(s_acc_mutex);
    return ret;
}

/* --------------------------------------------------------------------------
 * Flush task -- drains the accumulator on the idle timer.
 * -------------------------------------------------------------------------- */
static void flush_task_fn(void *arg)
{
    (void)arg;
    const TickType_t poll_ticks    = pdMS_TO_TICKS(UDP_LOG_POLL_MS);
    const TickType_t timeout_ticks = pdMS_TO_TICKS(UDP_LOG_FLUSH_TIMEOUT_MS);

    while (s_running) {
        vTaskDelay(poll_ticks);
        if (!s_acc_mutex) continue;
        if (xSemaphoreTake(s_acc_mutex, portMAX_DELAY) != pdTRUE) continue;

        if (s_acc_len > 0 &&
            (xTaskGetTickCount() - s_acc_last_add) >= timeout_ticks) {
            flush_locked();
        }

        xSemaphoreGive(s_acc_mutex);
    }

    s_flush_task = NULL;
    vTaskDelete(NULL);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */
esp_err_t udp_log_init(void)
{
    if (s_installed) return ESP_OK;

    s_init_mutex = xSemaphoreCreateMutex();
    s_acc_mutex  = xSemaphoreCreateMutex();
    if (!s_init_mutex || !s_acc_mutex) {
        if (s_init_mutex) { vSemaphoreDelete(s_init_mutex); s_init_mutex = NULL; }
        if (s_acc_mutex)  { vSemaphoreDelete(s_acc_mutex);  s_acc_mutex  = NULL; }
        return ESP_FAIL;
    }

    s_running = true;
    if (xTaskCreate(flush_task_fn, "udp_log", UDP_LOG_FLUSH_STACK, NULL,
                    UDP_LOG_FLUSH_PRIO, &s_flush_task) != pdPASS) {
        s_running = false;
        vSemaphoreDelete(s_init_mutex);
        vSemaphoreDelete(s_acc_mutex);
        s_init_mutex = NULL;
        s_acc_mutex  = NULL;
        return ESP_FAIL;
    }

    s_prev_vprintf = esp_log_set_vprintf(udp_log_vprintf_hook);
    s_installed    = true;
    return ESP_OK;
}

void udp_log_deinit(void)
{
    if (!s_installed) return;

    esp_log_set_vprintf(s_prev_vprintf);
    s_prev_vprintf = NULL;
    s_installed    = false;

    /* Tell the flush task to exit; it will self-delete on the next tick. */
    s_running = false;

    int fd = atomic_exchange(&s_sock, -1);
    if (fd >= 0) {
        close(fd);
    }

    if (s_init_mutex) {
        vSemaphoreDelete(s_init_mutex);
        s_init_mutex = NULL;
    }
    if (s_acc_mutex) {
        vSemaphoreDelete(s_acc_mutex);
        s_acc_mutex = NULL;
    }
}

#endif /* UDP_LOG_HOST && UDP_LOG_PORT */
