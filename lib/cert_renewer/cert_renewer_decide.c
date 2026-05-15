/*
 * cert_renewer_decide.c -- pure renewal decision function
 *
 * Native-testable: no ESP-IDF, no FreeRTOS, no NVS, no wolfSSL.
 */

#include "cert_renewer_decide.h"

/* Minimum plausible Unix epoch: 2020-01-01 00:00:00 UTC.
 * Below this value the clock is almost certainly un-synced (reset state is 0
 * or some early epoch).  Matches MIN_PLAUSIBLE_EPOCH in main/wifi.c.
 * TODO: share by promoting MIN_PLAUSIBLE_EPOCH to wifi.h.            */
#define MIN_PLAUSIBLE_EPOCH  ((time_t)1577836800)

renewal_decision_t cert_renewer_decide(time_t   now,
                                       uint64_t not_after,
                                       uint32_t window_days)
{
    if (now < MIN_PLAUSIBLE_EPOCH) {
        return RENEWAL_DECISION_SKIP_NO_CLOCK;
    }

    /* not_after == 0 is a sentinel meaning "NotAfter could not be parsed";
     * treat it as already expired to trigger a fresh enrollment. */
    if (not_after == 0) {
        return RENEWAL_DECISION_RENEW_NOW;
    }

    int64_t remaining_sec = (int64_t)not_after - (int64_t)now;
    int64_t window_sec    = (int64_t)window_days * 86400LL;

    if (remaining_sec <= window_sec) {
        return RENEWAL_DECISION_RENEW_NOW;
    }

    return RENEWAL_DECISION_SKIP_VALID;
}
