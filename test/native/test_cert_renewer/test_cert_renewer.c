/*
 * test_cert_renewer.c -- unit tests for cert_renewer_decide()
 *
 * Tests the pure decision function from lib/cert_renewer/cert_renewer_decide.c.
 * No ESP-IDF, FreeRTOS, NVS, or hardware dependencies; compiled for the native
 * host target under PlatformIO.
 *
 * What IS tested here (pure logic, native-safe):
 *   cert_renewer_decide(now, not_after, window_days) -> renewal_decision_t
 *
 * What is NOT tested here (on-device only):
 *   cert_renewer_start()          -- creates a FreeRTOS task; untestable natively.
 *   scep_enroll()                 -- network I/O + RSA keygen.
 *   smart_eap_apply_creds()       -- calls esp_eap_client_* (ESP-IDF driver).
 *   esp_wifi_disconnect()         -- Wi-Fi driver.
 *   cred_store_load / save        -- NVS backend.
 *
 * Truth table:
 *
 *  # | now                  | not_after           | window_days | expected
 *  --|----------------------|---------------------|-------------|---------------------
 *  1 | 0 (cold boot)        | any                 | 7           | SKIP_NO_CLOCK
 *  2 | == MIN_PLAUSIBLE     | now + 30d           | 7           | SKIP_VALID   (boundary: strict < so equal is synced)
 *  3 | MIN_PLAUSIBLE+1      | now + 30d           | 7           | SKIP_VALID
 *  4 | MIN_PLAUSIBLE+1      | now + 8d            | 7           | SKIP_VALID (8d > 7d)
 *  5 | MIN_PLAUSIBLE+1      | now + 7d            | 7           | SKIP_VALID (== edge: remaining_sec==window_sec, < is false)
 *  6 | MIN_PLAUSIBLE+1      | now + 6d            | 7           | RENEW_NOW  (inside)
 *  7 | MIN_PLAUSIBLE+1      | past                | 7           | RENEW_NOW  (expired)
 *  8 | MIN_PLAUSIBLE+1      | 0                   | 7           | RENEW_NOW_CORRUPT (sentinel)
 *  9 | MIN_PLAUSIBLE+1      | now                 | 7           | RENEW_NOW  (expires now)
 * 10 | MIN_PLAUSIBLE+1      | now + 1d            | 1           | SKIP_VALID (== edge: remaining==window, < is false)
 * 11 | MIN_PLAUSIBLE+1      | now + 2d            | 1           | SKIP_VALID (2d > 1d)
 * 12 | MIN_PLAUSIBLE+1      | now + 100d          | 365         | RENEW_NOW  (100d < 365d window)
 */

#include "unity.h"
#include "cert_renewer_decide.h"
#include "wifi_state.h"   /* MIN_PLAUSIBLE_EPOCH */

#define DAY_SEC  ((uint64_t)86400)

void setUp(void)    {}
void tearDown(void) {}

/* --------------------------------------------------------------------------
 * Row 1: cold-boot epoch 0 -> SKIP_NO_CLOCK
 * -------------------------------------------------------------------------- */
void test_cold_boot_epoch_zero_skips(void)
{
    renewal_decision_t d = cert_renewer_decide(
        0,
        MIN_PLAUSIBLE_EPOCH + 30 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_NO_CLOCK, d);
}

/* --------------------------------------------------------------------------
 * Row 2: now exactly == MIN_PLAUSIBLE_EPOCH -> SKIP_VALID
 * The guard is strict: "now < MIN_PLAUSIBLE_EPOCH".  Equality means the clock
 * IS considered plausible, so the function continues to check the cert.
 * With 30 days remaining and a 7-day window the result is SKIP_VALID.
 * -------------------------------------------------------------------------- */
void test_exactly_min_plausible_is_valid_clock(void)
{
    renewal_decision_t d = cert_renewer_decide(
        MIN_PLAUSIBLE_EPOCH,
        (uint64_t)MIN_PLAUSIBLE_EPOCH + 30 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 3: cert 30 days out, window 7 days -> SKIP_VALID
 * -------------------------------------------------------------------------- */
void test_cert_30_days_out_window_7_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 30 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 4: cert 8 days out, window 7 days -> SKIP_VALID (8 > 7)
 * -------------------------------------------------------------------------- */
void test_cert_8_days_out_window_7_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 8 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 5: cert exactly 7 days out, window 7 days -> SKIP_VALID
 * remaining_sec == window_sec; condition is strict <, so equal is NOT renewal.
 * -------------------------------------------------------------------------- */
void test_cert_7_days_out_window_7_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 7 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 6: cert 6 days out, window 7 days -> RENEW_NOW (inside window)
 * -------------------------------------------------------------------------- */
void test_cert_6_days_out_window_7_renews(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 6 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 7: cert already expired -> RENEW_NOW
 * -------------------------------------------------------------------------- */
void test_expired_cert_renews(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(MIN_PLAUSIBLE_EPOCH - 1),
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 8: not_after == 0 sentinel -> RENEW_NOW_CORRUPT
 * The corrupt-cert path is distinguishable from a legitimately near-expiry
 * cert so callers can apply a longer backoff.
 * -------------------------------------------------------------------------- */
void test_not_after_zero_sentinel_renews_corrupt(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(now, 0, 7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW_CORRUPT, d);
}

/* --------------------------------------------------------------------------
 * Row 9: cert expires exactly now -> RENEW_NOW
 * -------------------------------------------------------------------------- */
void test_cert_expires_now_renews(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(now, (uint64_t)now, 7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 10: cert 1 day out, window 1 day -> SKIP_VALID
 * remaining_sec == window_sec; strict < means equal is NOT a renewal trigger.
 * -------------------------------------------------------------------------- */
void test_cert_1_day_out_window_1_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 1 * DAY_SEC,
        1);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 11: cert 2 days out, window 1 day -> SKIP_VALID (2 > 1)
 * -------------------------------------------------------------------------- */
void test_cert_2_days_out_window_1_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 2 * DAY_SEC,
        1);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 12: large window_days (365) triggers renewal when 100d remain
 * -------------------------------------------------------------------------- */
void test_large_window_triggers_renewal(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 100 * DAY_SEC,
        365);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 13: window_days == 0 means "never renew early" -- cert must expire
 * before renewal is triggered (remaining_sec <= 0).
 * -------------------------------------------------------------------------- */
void test_window_zero_cert_still_valid_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    /* Even 1 second of remaining life is outside the 0-day window. */
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 1,
        0);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 14: window_days == 0, cert expires exactly now -> remaining == 0 ->
 * SKIP_VALID (remaining_sec=0, window_sec=0; 0 < 0 is false).
 * To trigger renewal with window_days=0 the cert must already be expired
 * (remaining_sec < 0 < window_sec=0 ... no; actually remaining_sec < 0
 * and window_sec=0 gives remaining_sec < 0 which is true -> RENEW_NOW).
 * Exactly-now is the boundary case that is now SKIP.
 * -------------------------------------------------------------------------- */
void test_window_zero_cert_expires_now_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)now,
        0);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 15: clock exactly one second below MIN_PLAUSIBLE_EPOCH -> SKIP_NO_CLOCK
 * -------------------------------------------------------------------------- */
void test_one_below_min_plausible_skips(void)
{
    renewal_decision_t d = cert_renewer_decide(
        MIN_PLAUSIBLE_EPOCH - 1,
        (uint64_t)MIN_PLAUSIBLE_EPOCH + 30 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_NO_CLOCK, d);
}

/* --------------------------------------------------------------------------
 * Row 16: window_days = UINT32_MAX / 86400 -- enormous window.
 * If the cert has only 1 day remaining, it must still trigger renewal because
 * 86400 seconds < UINT32_MAX * 86400 seconds (overflows int64?).  Check that
 * the arithmetic saturates safely: window_sec = window_days * 86400LL.
 * For window_days = UINT32_MAX, window_sec = 4294967295 * 86400 = ~3.7e14,
 * which fits in int64_t (max ~9.2e18).  So a cert valid for only 1 day
 * (86400 s) has remaining_sec < window_sec -> RENEW_NOW.
 * -------------------------------------------------------------------------- */
void test_very_large_window_days_safe(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 1 * DAY_SEC,
        (uint32_t)0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 17: small but plausible clock values just above MIN_PLAUSIBLE_EPOCH
 * -------------------------------------------------------------------------- */
void test_exactly_min_plausible_plus_one_second(void)
{
    /* now = MIN_PLAUSIBLE_EPOCH + 1, not_after far in future */
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 365 * DAY_SEC,
        30);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 18: not_after == 1 (epoch 1 = 1970-01-01 00:00:01): treated as expired
 * relative to MIN_PLAUSIBLE_EPOCH, so remaining_sec < 0 <= window_sec -> RENEW
 * -------------------------------------------------------------------------- */
void test_not_after_epoch_one_is_expired(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(now, (uint64_t)1, 7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 19: cert expires in exactly window_days * 86400 + 1 seconds -> SKIP_VALID
 * -------------------------------------------------------------------------- */
void test_cert_one_second_past_window_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    uint32_t window_days = 14;
    /* remaining = window_days * 86400 + 1 > window_sec -> SKIP */
    uint64_t not_after = (uint64_t)(now) + (uint64_t)window_days * DAY_SEC + 1;
    renewal_decision_t d = cert_renewer_decide(now, not_after, window_days);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 20: cert expires in exactly window_days * 86400 seconds -> SKIP_VALID
 * remaining_sec == window_sec; strict < means the equal case does NOT renew.
 * -------------------------------------------------------------------------- */
void test_cert_exactly_at_window_boundary_skips(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    uint32_t window_days = 14;
    /* remaining == window_sec -> SKIP_VALID (boundary is strict <) */
    uint64_t not_after = (uint64_t)(now) + (uint64_t)window_days * DAY_SEC;
    renewal_decision_t d = cert_renewer_decide(now, not_after, window_days);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_VALID, d);
}

/* --------------------------------------------------------------------------
 * Row 21: now == not_after - 1 (one second before expiry) -> RENEW_NOW
 * (remaining_sec == 1, window_sec == 7 * 86400 > 1 -- inside window)
 * -------------------------------------------------------------------------- */
void test_one_second_before_expiry_in_window(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    uint64_t not_after = (uint64_t)(now) + 1;
    renewal_decision_t d = cert_renewer_decide(now, not_after, 7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
}

/* --------------------------------------------------------------------------
 * Row 22: RENEWAL_DECISION_SKIP_NO_CLOCK returned for any now < plausible
 *         regardless of what not_after is (even if not_after == 0)
 * -------------------------------------------------------------------------- */
void test_no_clock_overrides_sentinel_not_after(void)
{
    /* Even the zero-sentinel must not override the clock-not-synced check */
    renewal_decision_t d = cert_renewer_decide(
        MIN_PLAUSIBLE_EPOCH - 100,
        0,   /* sentinel */
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_SKIP_NO_CLOCK, d);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cold_boot_epoch_zero_skips);
    RUN_TEST(test_exactly_min_plausible_is_valid_clock);
    RUN_TEST(test_cert_30_days_out_window_7_skips);
    RUN_TEST(test_cert_8_days_out_window_7_skips);
    RUN_TEST(test_cert_7_days_out_window_7_skips);
    RUN_TEST(test_cert_6_days_out_window_7_renews);
    RUN_TEST(test_expired_cert_renews);
    RUN_TEST(test_not_after_zero_sentinel_renews_corrupt);
    RUN_TEST(test_cert_expires_now_renews);
    RUN_TEST(test_cert_1_day_out_window_1_skips);
    RUN_TEST(test_cert_2_days_out_window_1_skips);
    RUN_TEST(test_large_window_triggers_renewal);
    /* New edge-case tests */
    RUN_TEST(test_window_zero_cert_still_valid_skips);
    RUN_TEST(test_window_zero_cert_expires_now_skips);
    RUN_TEST(test_one_below_min_plausible_skips);
    RUN_TEST(test_very_large_window_days_safe);
    /* Additional boundary / branch coverage */
    RUN_TEST(test_exactly_min_plausible_plus_one_second);
    RUN_TEST(test_not_after_epoch_one_is_expired);
    RUN_TEST(test_cert_one_second_past_window_skips);
    RUN_TEST(test_cert_exactly_at_window_boundary_skips);
    RUN_TEST(test_one_second_before_expiry_in_window);
    RUN_TEST(test_no_clock_overrides_sentinel_not_after);
    return UNITY_END();
}
