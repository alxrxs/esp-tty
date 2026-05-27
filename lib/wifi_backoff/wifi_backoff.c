/*
 * wifi_backoff.c -- pure helpers for the WiFi reconnect-backoff math.
 * See wifi_backoff.h for the public contract.
 *
 * The reason-code list mirrors esp_wifi_types_generic.h's wifi_err_reason_t.
 * Numeric literals are used (instead of including esp_wifi_types.h directly)
 * so this translation unit compiles unchanged for the native test target.
 * Each code is documented with its IEEE 802.11 / ESP-IDF meaning and the
 * specific security threat it indicates.
 */

#include "wifi_backoff.h"

bool wifi_backoff_is_security_failure(int reason)
{
    switch (reason) {
        /* IEEE 802.11 standard reason codes (1..67) where the disconnect
         * was caused by an authentication, key-management, or cipher-
         * negotiation failure -- not a transient radio problem. */

        case 2:   /* AUTH_EXPIRE              -- 802.11 auth state lost */
        case 14:  /* MIC_FAILURE              -- TKIP MIC fail; replay or
                   *                             forgery indicator.  IEEE
                   *                             countermeasure is 60 s of
                   *                             back-off after 2 fails in
                   *                             60 s; our 5 min cap covers
                   *                             that and then some. */
        case 15:  /* 4WAY_HANDSHAKE_TIMEOUT   -- PSK/PMK mismatch or AP
                   *                             dropped EAPOL */
        case 16:  /* GROUP_KEY_UPDATE_TIMEOUT -- group rekey failed */
        case 17:  /* IE_IN_4WAY_DIFFERS       -- RSN IE mismatch between
                   *                             beacon and 4-way; possible
                   *                             rogue-AP / downgrade attack */
        case 18:  /* GROUP_CIPHER_INVALID     -- AP advertises a cipher we
                   *                             reject */
        case 19:  /* PAIRWISE_CIPHER_INVALID  -- ditto, pairwise */
        case 20:  /* AKMP_INVALID             -- AKM suite mismatch */
        case 23:  /* 802_1X_AUTH_FAILED       -- RADIUS rejected the EAP
                   *                             credentials */
        case 24:  /* CIPHER_SUITE_REJECTED    -- AP refused our cipher */
        case 29:  /* BAD_CIPHER_OR_AKM        -- generic AKM/cipher reject */
        case 49:  /* INVALID_PMKID            -- PMK caching mismatch; can
                   *                             indicate a forged AP */

        /* ESP-IDF synthetic reason codes (>=200) raised by the supplicant
         * when authentication failed before the standard reason codes are
         * meaningful. */
        case 202: /* AUTH_FAIL                -- supplicant gave up auth */
        case 203: /* ASSOC_FAIL               -- association rejected */
        case 204: /* HANDSHAKE_TIMEOUT        -- generic handshake timeout */
        case 210: /* NO_AP_FOUND_W_COMPATIBLE_SECURITY -- our security
                   *                             config does not match any
                   *                             AP we can see; treat as
                   *                             config failure, not radio */
        case 211: /* NO_AP_FOUND_IN_AUTHMODE_THRESHOLD -- ditto, authmode */
            return true;

        /* WIFI_REASON_AUTH_LEAVE (3) is intentionally NOT classified as
         * security: it is the disconnect reason the AP sends when WE walk
         * away, and is also what some APs return on planned roams.  An
         * attacker who can spoof deauths can already DoS us; counting that
         * as security_fail just amplifies the DoS by stretching our
         * reconnect to 5 min.  Treat as LINK (60 s cap, fast recovery). */

        default:
            return false;
    }
}

uint32_t wifi_backoff_compute_ms(int retry_n,
                                 bool security_fail,
                                 uint32_t random_u32)
{
    if (retry_n <= 0) return 0;

    /* Cap the shift exponent before doing the shift to avoid UB on large
     * retry counts.  WIFI_BACKOFF_SHIFT_MAX = 6 means base saturates at
     * 64 s before the cap clamp; both caps are below 64 s for LINK and
     * well below for SECURITY, so the cap clamp dominates. */
    int shift = retry_n - 1;
    if (shift > WIFI_BACKOFF_SHIFT_MAX) shift = WIFI_BACKOFF_SHIFT_MAX;

    uint32_t base_ms = 1000u << shift;
    uint32_t cap_ms = security_fail ? WIFI_BACKOFF_SECURITY_CAP_MS
                                    : WIFI_BACKOFF_LINK_CAP_MS;
    if (base_ms > cap_ms) base_ms = cap_ms;

    uint32_t jitter_window = base_ms / 4u;
    if (jitter_window == 0u) return base_ms;

    /* Signed arithmetic: (rand % 2W) - W lands in [-W, W-1].  Without the
     * cast to int32_t the subtraction would wrap through UINT32_MAX, which
     * IS defined modular arithmetic but obscures intent and is fragile if
     * `base_ms + jitter` is ever reconsidered. */
    int32_t jitter_signed =
        (int32_t)(random_u32 % (2u * jitter_window)) - (int32_t)jitter_window;
    int64_t computed = (int64_t)base_ms + (int64_t)jitter_signed;
    if (computed < 0) return 0;
    if (computed > (int64_t)UINT32_MAX) return UINT32_MAX;
    return (uint32_t)computed;
}
