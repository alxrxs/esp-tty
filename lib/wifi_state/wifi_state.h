/*
 * wifi_state.h -- WiFi state-machine decision logic for esp-tty
 *
 * Exposes the pure `wifi_decide_next_step()` function that maps the current
 * enrollment/connectivity state onto the next action the state machine
 * should take.  All inputs are plain booleans/integers; no ESP-IDF types are
 * used here so the function can be unit-tested natively.
 *
 * The ESP-IDF driver lifecycle and FreeRTOS event-group machinery live in
 * main/wifi.c (wifi_init_smart()).  Only the decision logic lives here.
 */

#pragma once

#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimum plausible Unix epoch: 2020-01-01 00:00:00 UTC.
 * A clock value below this threshold is almost certainly un-synced (reset
 * state is 0 or some early epoch).  Shared across wifi.c, cert_renewer_decide.c,
 * and the native test suite. */
#define MIN_PLAUSIBLE_EPOCH  ((time_t)1577836800UL)

/* --------------------------------------------------------------------------
 * Decision enum
 * -------------------------------------------------------------------------- */

typedef enum {
    /* Connect straight to the enterprise (WPA3-EAP-TLS) network. */
    WIFI_DECISION_ENTERPRISE,

    /* Connect to the bootstrap (PSK) network, sync NTP, then try enterprise.
     * The state machine does NOT run SCEP enrollment after NTP sync;
     * it proceeds directly to enterprise once time is known.
     * Used when NTP_BEFORE_EAPTLS is set and time is not yet synced. */
    WIFI_DECISION_BOOTSTRAP_NTP_ONLY,

    /* Connect to the bootstrap (PSK) network, sync NTP, run SCEP enrollment,
     * then reboot (fresh state after successful enrollment).
     * Used when no cert is stored, or cert is expired, or enterprise has
     * failed enough times that re-enrollment seems warranted. */
    WIFI_DECISION_BOOTSTRAP_FULL,
} wifi_decision_t;

/* --------------------------------------------------------------------------
 * Pure decision function
 *
 * Parameters
 * ----------
 * cert_present
 *   true  -- cred_store_load() returned ESP_OK (device cert is in NVS).
 *   false -- no stored credential; enrollment required.
 *
 * cert_expired
 *   true  -- cert NotAfter is within 24 hours (or already past).
 *   false -- cert still has more than 24 hours before it expires.
 *   Ignored when cert_present is false.
 *
 * ntp_synced
 *   true  -- time(NULL) returned a plausible epoch (>= 2020).
 *   false -- clock is still at reset value (e.g. 0 or 1970).
 *
 * ntp_before_eaptls_required
 *   true  -- NTP_BEFORE_EAPTLS is defined and non-zero.
 *   false -- not required; attempt enterprise directly.
 *
 * no_ntp_mode
 *   true  -- SCEP_NO_NTP_USE_ISSUANCE_TIME is defined.  Every boot must
 *            perform a fresh SCEP enrollment so the issued cert's NotBefore
 *            can be used as the local-clock anchor.  When true this flag
 *            unconditionally returns WIFI_DECISION_BOOTSTRAP_FULL regardless
 *            of cert_present, cert_expired, or ntp_synced -- all other inputs
 *            are irrelevant.
 *   false -- normal behaviour; remaining rules apply.
 *
 * enterprise_attempts_so_far
 *   How many times enterprise mode has been tried in this boot cycle
 *   (including the attempt that just failed, if any).  0 means no attempt
 *   has been made yet.
 *
 * enterprise_retry_max
 *   Maximum number of enterprise attempts before falling back to bootstrap.
 *   0 means unlimited (never fall back due to attempt count alone).
 *
 * Returns
 * -------
 * The next action the caller should take.  The caller is responsible for
 * executing it (driver lifecycle, NTP wait, SCEP enroll, reboot, etc.).
 * -------------------------------------------------------------------------- */
wifi_decision_t wifi_decide_next_step(
    bool cert_present,
    bool cert_expired,
    bool ntp_synced,
    bool ntp_before_eaptls_required,
    bool no_ntp_mode,
    int  enterprise_attempts_so_far,
    int  enterprise_retry_max);

#ifdef __cplusplus
}
#endif
