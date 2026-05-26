/*
 * cert_renewer_decide.c -- pure renewal decision function
 *
 * Native-testable: no ESP-IDF, no FreeRTOS, no NVS, no wolfSSL.
 */

#include "cert_renewer_decide.h"
#include "wifi_state.h"   /* MIN_PLAUSIBLE_EPOCH */

renewal_decision_t cert_renewer_decide(time_t   now,
                                       uint64_t not_after,
                                       uint32_t window_days)
{
    if (now < MIN_PLAUSIBLE_EPOCH) {
        return RENEWAL_DECISION_SKIP_NO_CLOCK;
    }

    /* not_after == 0 is a sentinel meaning "NotAfter could not be parsed";
     * return RENEW_NOW_CORRUPT so the caller can distinguish a corrupt cert
     * from a legitimately near-expiry cert and apply a longer backoff. */
    if (not_after == 0) {
        return RENEWAL_DECISION_RENEW_NOW_CORRUPT;
    }

    int64_t remaining_sec = (int64_t)not_after - (int64_t)now;
    int64_t window_sec    = (int64_t)window_days * 86400LL;

    if (remaining_sec < window_sec) {
        return RENEWAL_DECISION_RENEW_NOW;
    }

    return RENEWAL_DECISION_SKIP_VALID;
}
