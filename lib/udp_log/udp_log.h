/*
 * udp_log.h -- UDP log mirror public API
 *
 * When UDP_LOG_HOST and UDP_LOG_PORT are both defined in config.h, every
 * ESP_LOG* line is mirrored as a UDP datagram to the configured host/port
 * in addition to appearing on UART0 as usual.
 *
 * Usage:
 *   1. Define in config.h:
 *        #define UDP_LOG_HOST  "10.57.16.10"
 *        #define UDP_LOG_PORT  5514
 *   2. Call udp_log_init() once after Wi-Fi is up and an IP address has
 *      been obtained.
 *   3. Capture on the receiving host with:
 *        nc -ul 5514
 *
 * When the macros are not defined, this header compiles to no-ops and no
 * UDP code is linked in.
 *
 * See lib/udp_log/README.md for full documentation.
 */

#pragma once

#if defined(UDP_LOG_HOST) && defined(UDP_LOG_PORT)

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * udp_log_init() -- install the vprintf hook.
 *
 * Safe to call exactly once after Wi-Fi is associated and an IP address is
 * available.  Calling it before the network is up means log lines produced
 * before udp_log_init() are only visible on UART0 (they never hit UDP).
 *
 * Returns ESP_OK on success, ESP_FAIL if socket creation fails.
 * The UART log path is installed regardless of the return value.
 */
esp_err_t udp_log_init(void);

/*
 * udp_log_deinit() -- uninstall the vprintf hook.
 *
 * Restores the previous vprintf handler and closes the UDP socket.
 * Idempotent: safe to call even if udp_log_init() was never called or
 * failed.
 */
void udp_log_deinit(void);

#ifdef __cplusplus
}
#endif

#else /* UDP_LOG_HOST && UDP_LOG_PORT not both defined */

/* No-op stubs so call sites compile without #ifdef guards. */
#include "esp_err.h"
static inline esp_err_t udp_log_init(void)  { return ESP_OK; }
static inline void      udp_log_deinit(void) { }

#endif /* UDP_LOG_HOST && UDP_LOG_PORT */
