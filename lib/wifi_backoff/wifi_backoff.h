/*
 * wifi_backoff.h -- pure helpers for the WiFi disconnect-reason classifier
 * and exponential-backoff math used by main/wifi.c.
 *
 * Extracted from the event handler so the classification and arithmetic can
 * be unit-tested on the host without ESP-IDF, FreeRTOS, or a real radio.
 * The full disconnect-handler logic (event group, FreeRTOS timer, retry
 * counter) lives in main/wifi.c; only the pure functions live here.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backoff caps used by main/wifi.c.  Exposed for tests and so call sites
 * don't sprinkle magic numbers. */
#define WIFI_BACKOFF_LINK_CAP_MS       60000u
#define WIFI_BACKOFF_SECURITY_CAP_MS  300000u

/* Largest shift used by the exponential formula (1 << SHIFT_MAX) before the
 * cap clamps the result.  Caps the shift well below 32 so we never come
 * close to undefined-behaviour territory on 32-bit math. */
#define WIFI_BACKOFF_SHIFT_MAX  6

/* wifi_backoff_is_security_failure -- classify an 802.11 disconnect reason
 * code as security-relevant (long backoff) or transient/link (short backoff).
 *
 * Security-relevant reasons indicate authentication, key-management, cipher
 * negotiation, or 802.1X/EAP failures.  Hammering these saturates upstream
 * RADIUS audit logs and, for MIC failures specifically, helps an attacker
 * brute-force the TKIP MIC; the IEEE 802.11 spec recommends ~60 s of
 * countermeasures after two MIC failures within 60 s, and our 5-minute cap
 * easily envelopes that.
 *
 * The `reason` argument is a wifi_err_reason_t from esp_wifi_types.h, but
 * this helper takes a plain int so it remains buildable in native tests
 * without pulling in ESP-IDF headers. */
bool wifi_backoff_is_security_failure(int reason);

/* wifi_backoff_compute_ms -- compute the (post-jitter) backoff delay in ms
 * for the `retry_n`-th consecutive retry (1-based: first retry is retry_n=1).
 *
 * Math: base = min(1000 * 2^(min(retry_n-1, SHIFT_MAX)), cap).
 *       jitter = +/- (base / 4), uniformly random.
 *       result = clamp_lo(base + jitter, 0).
 *
 * `random_u32` is the source of jitter bits (esp_random() on target,
 * deterministic stub in tests).  When `jitter_window` is zero, returns base.
 *
 * Cap is WIFI_BACKOFF_SECURITY_CAP_MS for security failures, else
 * WIFI_BACKOFF_LINK_CAP_MS.  Returns 0 if retry_n <= 0. */
uint32_t wifi_backoff_compute_ms(int retry_n,
                                 bool security_fail,
                                 uint32_t random_u32);

#ifdef __cplusplus
}
#endif
