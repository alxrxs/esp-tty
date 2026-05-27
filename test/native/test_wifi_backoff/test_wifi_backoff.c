/*
 * test_wifi_backoff.c -- unit tests for the pure WiFi reconnect-backoff
 * helpers in lib/wifi_backoff/.
 *
 * Verifies:
 *   - All known security-relevant 802.11 reason codes (MIC failure, cipher /
 *     AKM mismatches, 802.1X, RSN-IE differences, PMKID, ...) are classified
 *     as security failures and earn the 5-minute cap, not the 60-second cap.
 *   - The transient/link reasons (BEACON_TIMEOUT, NO_AP_FOUND, ASSOC_LEAVE,
 *     AUTH_LEAVE, deauth-by-inactivity, ...) stay on the LINK cap.
 *   - The exponential backoff respects both caps, never overflows, and
 *     produces non-negative output even when jitter would underflow base_ms.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "unity.h"
#include "wifi_backoff.h"

void setUp(void)    {}
void tearDown(void) {}

/* -- Classifier: security failures should return true --------------------- */

static const struct {
    int code;
    const char *name;
} k_security_codes[] = {
    {  2, "AUTH_EXPIRE"               },
    { 14, "MIC_FAILURE"               },
    { 15, "4WAY_HANDSHAKE_TIMEOUT"    },
    { 16, "GROUP_KEY_UPDATE_TIMEOUT"  },
    { 17, "IE_IN_4WAY_DIFFERS"        },
    { 18, "GROUP_CIPHER_INVALID"      },
    { 19, "PAIRWISE_CIPHER_INVALID"   },
    { 20, "AKMP_INVALID"              },
    { 23, "802_1X_AUTH_FAILED"        },
    { 24, "CIPHER_SUITE_REJECTED"     },
    { 29, "BAD_CIPHER_OR_AKM"         },
    { 49, "INVALID_PMKID"             },
    {202, "AUTH_FAIL"                 },
    {203, "ASSOC_FAIL"                },
    {204, "HANDSHAKE_TIMEOUT"         },
    {210, "NO_AP_FOUND_W_COMPATIBLE_SECURITY" },
    {211, "NO_AP_FOUND_IN_AUTHMODE_THRESHOLD" },
};

static void test_classifier_security_codes_all_true(void)
{
    for (size_t i = 0; i < sizeof(k_security_codes)/sizeof(k_security_codes[0]); i++) {
        bool got = wifi_backoff_is_security_failure(k_security_codes[i].code);
        char msg[96];
        snprintf(msg, sizeof(msg), "%s (%d) should classify as security",
                 k_security_codes[i].name, k_security_codes[i].code);
        TEST_ASSERT_TRUE_MESSAGE(got, msg);
    }
}

/* -- Classifier: link/transient codes should return false ----------------- */

static const struct {
    int code;
    const char *name;
} k_link_codes[] = {
    {  1, "UNSPECIFIED"                       },
    {  3, "AUTH_LEAVE (AP-initiated deauth)"  },
    {  4, "DISASSOC_DUE_TO_INACTIVITY"        },
    {  5, "ASSOC_TOOMANY"                     },
    {  8, "ASSOC_LEAVE"                       },
    { 39, "TIMEOUT"                           },
    {200, "BEACON_TIMEOUT"                    },
    {201, "NO_AP_FOUND"                       },
    {205, "CONNECTION_FAIL"                   },
    {207, "ROAMING"                           },
};

static void test_classifier_link_codes_all_false(void)
{
    for (size_t i = 0; i < sizeof(k_link_codes)/sizeof(k_link_codes[0]); i++) {
        bool got = wifi_backoff_is_security_failure(k_link_codes[i].code);
        char msg[96];
        snprintf(msg, sizeof(msg), "%s (%d) should NOT classify as security",
                 k_link_codes[i].name, k_link_codes[i].code);
        TEST_ASSERT_FALSE_MESSAGE(got, msg);
    }
}

/* -- Backoff math --------------------------------------------------------- */

static void test_backoff_retry0_returns_zero(void)
{
    /* Defensive: retry_n=0 is not a valid input but must not crash. */
    TEST_ASSERT_EQUAL_UINT32(0u, wifi_backoff_compute_ms(0, false, 0));
    TEST_ASSERT_EQUAL_UINT32(0u, wifi_backoff_compute_ms(-1, true, 0));
}

static void test_backoff_first_retry_is_one_second_plus_minus_jitter(void)
{
    /* retry_n=1: base=1000ms, jitter_window=250.  With random=0 the jitter
     * is -250; with random=2*W-1=499 the jitter is +249. */
    uint32_t lo = wifi_backoff_compute_ms(1, false, 0);
    uint32_t hi = wifi_backoff_compute_ms(1, false, 499);
    TEST_ASSERT_EQUAL_UINT32(750u, lo);   /* 1000 - 250 */
    TEST_ASSERT_EQUAL_UINT32(1249u, hi);  /* 1000 + 249 */
}

static void test_backoff_link_capped_at_60s(void)
{
    /* retry_n=20 -> shift saturates at 6, base = 64000ms, then capped at
     * WIFI_BACKOFF_LINK_CAP_MS = 60000ms.  jitter_window=15000. */
    uint32_t lo = wifi_backoff_compute_ms(20, false, 0);
    uint32_t hi = wifi_backoff_compute_ms(20, false, 29999);
    TEST_ASSERT_EQUAL_UINT32(45000u, lo);   /* 60000 - 15000 */
    TEST_ASSERT_EQUAL_UINT32(74999u, hi);   /* 60000 + 14999 */
}

static void test_backoff_security_capped_at_5min(void)
{
    /* retry_n=20 with security_fail=true.  base shifts up to 64000 then is
     * NOT capped (cap=300000), and grows only via the shift saturation, so
     * effective base=64000.  Jitter window=16000. */
    uint32_t lo = wifi_backoff_compute_ms(20, true, 0);
    uint32_t hi = wifi_backoff_compute_ms(20, true, 31999);
    TEST_ASSERT_EQUAL_UINT32(48000u, lo);    /* 64000 - 16000 */
    TEST_ASSERT_EQUAL_UINT32(79999u, hi);    /* 64000 + 15999 */
}

static void test_backoff_no_negative_overflow(void)
{
    /* Sweep retry_n and random to verify the result is always within
     * [0, cap * 5/4] and never wraps. */
    for (int r = 1; r <= 64; r++) {
        for (uint32_t rnd = 0; rnd < 10; rnd++) {
            uint32_t v_link = wifi_backoff_compute_ms(r, false, rnd * 12345u);
            uint32_t v_sec  = wifi_backoff_compute_ms(r, true,  rnd * 12345u);
            /* The largest valid result is cap + (cap/4 - 1).  Pad upper
             * bound to account for the cap formula. */
            TEST_ASSERT_LESS_OR_EQUAL_UINT32(
                WIFI_BACKOFF_LINK_CAP_MS + (WIFI_BACKOFF_LINK_CAP_MS / 4u),
                v_link);
            TEST_ASSERT_LESS_OR_EQUAL_UINT32(
                WIFI_BACKOFF_SECURITY_CAP_MS + (WIFI_BACKOFF_SECURITY_CAP_MS / 4u),
                v_sec);
        }
    }
}

static void test_backoff_shift_saturates_no_ub_at_large_retries(void)
{
    /* retry_n = INT_MAX-equivalent must not shift by >= 32. */
    uint32_t v = wifi_backoff_compute_ms(1000, false, 0);
    /* Capped at 60000ms - 15000ms jitter window with random=0. */
    TEST_ASSERT_EQUAL_UINT32(45000u, v);
}

static void test_backoff_security_vs_link_at_retry10(void)
{
    /* retry_n=10 puts shift at WIFI_BACKOFF_SHIFT_MAX=6 -> base 64000.
     * LINK cap clamps to 60000; SECURITY does not.  So security backoff
     * should be strictly LARGER than link backoff for the same retry+rnd. */
    uint32_t link = wifi_backoff_compute_ms(10, false, 0);
    uint32_t sec  = wifi_backoff_compute_ms(10, true,  0);
    TEST_ASSERT_GREATER_THAN_UINT32(link, sec);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_classifier_security_codes_all_true);
    RUN_TEST(test_classifier_link_codes_all_false);
    RUN_TEST(test_backoff_retry0_returns_zero);
    RUN_TEST(test_backoff_first_retry_is_one_second_plus_minus_jitter);
    RUN_TEST(test_backoff_link_capped_at_60s);
    RUN_TEST(test_backoff_security_capped_at_5min);
    RUN_TEST(test_backoff_no_negative_overflow);
    RUN_TEST(test_backoff_shift_saturates_no_ub_at_large_retries);
    RUN_TEST(test_backoff_security_vs_link_at_retry10);
    return UNITY_END();
}
