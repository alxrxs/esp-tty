/*
 * wifi_state.c -- WiFi state-machine decision logic (pure function)
 *
 * See wifi_state.h for the full contract.
 *
 * Decision table (evaluated top-to-bottom; first match wins):
 *
 *  no_ntp | cert_present | cert_expired | ntp_synced | ntp_req | attempts >= max | decision
 *  -------|--------------|--------------|------------|---------|-----------------|----------
 *    yes  |      -       |      -       |     -      |    -    |        -        | BOOTSTRAP_FULL
 *     no  |      no      |      -       |     -      |    -    |        -        | BOOTSTRAP_FULL
 *     no  |     yes      |     yes      |     -      |    -    |        -        | BOOTSTRAP_FULL
 *     no  |     yes      |      no      |     -      |    -    |   yes (>0,>=max)| BOOTSTRAP_FULL
 *     no  |     yes      |      no      |     no     |   yes   |       no        | BOOTSTRAP_NTP_ONLY
 *     no  |     yes      |      no      |    any     |    no   |       no        | ENTERPRISE
 *     no  |     yes      |      no      |    yes     |   yes   |       no        | ENTERPRISE
 */

#include "wifi_state.h"

wifi_decision_t wifi_decide_next_step(
    bool cert_present,
    bool cert_expired,
    bool ntp_synced,
    bool ntp_before_eaptls_required,
    bool no_ntp_mode,
    int  enterprise_attempts_so_far,
    int  enterprise_retry_max)
{
    /* Rule 0: no-NTP mode -- every boot is a fresh enrollment so the issued
     * cert's NotBefore can seed the local clock.  Overrides all other inputs. */
    if (no_ntp_mode) {
        return WIFI_DECISION_BOOTSTRAP_FULL;
    }

    /* Rule 1: No cert -- must enroll. */
    if (!cert_present) {
        return WIFI_DECISION_BOOTSTRAP_FULL;
    }

    /* Rule 2: Cert expired (or within 24 h of expiry) -- re-enroll. */
    if (cert_expired) {
        return WIFI_DECISION_BOOTSTRAP_FULL;
    }

    /* Rule 3: Enterprise has exhausted its retry budget -- fall back to
     * bootstrap (re-enroll in case RADIUS is rejecting the cert). */
    if (enterprise_retry_max > 0 &&
        enterprise_attempts_so_far >= enterprise_retry_max) {
        return WIFI_DECISION_BOOTSTRAP_FULL;
    }

    /* Rule 4: Cert is valid, retry budget not exhausted, but NTP is required
     * before EAP-TLS and time is not yet synced -- bootstrap NTP only. */
    if (ntp_before_eaptls_required && !ntp_synced) {
        return WIFI_DECISION_BOOTSTRAP_NTP_ONLY;
    }

    /* Rule 5: All clear -- go straight to enterprise. */
    return WIFI_DECISION_ENTERPRISE;
}
