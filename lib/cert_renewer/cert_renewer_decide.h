/*
 * cert_renewer_decide.h -- pure renewal decision function
 *
 * Extracted from main/cert_renewer.c so the decision logic can be unit-tested
 * natively (no ESP-IDF, no FreeRTOS).
 *
 * The on-device renewal task and esp_eap_client_* reconfiguration are in
 * main/cert_renewer.c and are not testable at the native layer.
 */

#pragma once

#include <time.h>
#include <stdint.h>

typedef enum {
    RENEWAL_DECISION_SKIP_NO_CLOCK,  /* time(NULL) < MIN_PLAUSIBLE_EPOCH       */
    RENEWAL_DECISION_SKIP_VALID,     /* cert valid, far from expiry             */
    RENEWAL_DECISION_RENEW_NOW,      /* inside window, past expiry, or sentinel */
} renewal_decision_t;

/*
 * cert_renewer_decide -- pure function, no side effects, native-testable.
 *
 * Parameters:
 *   now         -- current Unix epoch (from time(NULL))
 *   not_after   -- cert NotAfter epoch (from cred_store_t.not_after).
 *                  0 is a sentinel meaning "could not be parsed" -- treated
 *                  as already expired (RENEW_NOW).
 *   window_days -- renew when fewer than this many days remain before expiry.
 *
 * Returns one of the RENEWAL_DECISION_* values above.
 */
renewal_decision_t cert_renewer_decide(time_t   now,
                                       uint64_t not_after,
                                       uint32_t window_days);
