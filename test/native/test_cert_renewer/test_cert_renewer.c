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
 *  5 | MIN_PLAUSIBLE+1      | now + 7d            | 7           | RENEW_NOW  (== edge)
 *  6 | MIN_PLAUSIBLE+1      | now + 6d            | 7           | RENEW_NOW  (inside)
 *  7 | MIN_PLAUSIBLE+1      | past                | 7           | RENEW_NOW  (expired)
 *  8 | MIN_PLAUSIBLE+1      | 0                   | 7           | RENEW_NOW  (sentinel)
 *  9 | MIN_PLAUSIBLE+1      | now                 | 7           | RENEW_NOW  (expires now)
 * 10 | MIN_PLAUSIBLE+1      | now + 1d            | 1           | RENEW_NOW  (== edge)
 * 11 | MIN_PLAUSIBLE+1      | now + 2d            | 1           | SKIP_VALID (2d > 1d)
 * 12 | MIN_PLAUSIBLE+1      | now + 100d          | 365         | RENEW_NOW  (100d < 365d window)
 */

#include "unity.h"
#include "cert_renewer_decide.h"

/* Matches the constant in cert_renewer_decide.c and wifi.c */
#define MIN_PLAUSIBLE_EPOCH  ((time_t)1577836800)   /* 2020-01-01 00:00:00 UTC */

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
 * Row 5: cert exactly 7 days out, window 7 days -> RENEW_NOW (== edge)
 * -------------------------------------------------------------------------- */
void test_cert_7_days_out_window_7_renews(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 7 * DAY_SEC,
        7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
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
 * Row 8: not_after == 0 sentinel -> RENEW_NOW
 * -------------------------------------------------------------------------- */
void test_not_after_zero_sentinel_renews(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(now, 0, 7);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
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
 * Row 10: cert 1 day out, window 1 day -> RENEW_NOW (== edge)
 * -------------------------------------------------------------------------- */
void test_cert_1_day_out_window_1_renews(void)
{
    time_t now = MIN_PLAUSIBLE_EPOCH + 1;
    renewal_decision_t d = cert_renewer_decide(
        now,
        (uint64_t)(now) + 1 * DAY_SEC,
        1);
    TEST_ASSERT_EQUAL_INT(RENEWAL_DECISION_RENEW_NOW, d);
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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cold_boot_epoch_zero_skips);
    RUN_TEST(test_exactly_min_plausible_is_valid_clock);
    RUN_TEST(test_cert_30_days_out_window_7_skips);
    RUN_TEST(test_cert_8_days_out_window_7_skips);
    RUN_TEST(test_cert_7_days_out_window_7_renews);
    RUN_TEST(test_cert_6_days_out_window_7_renews);
    RUN_TEST(test_expired_cert_renews);
    RUN_TEST(test_not_after_zero_sentinel_renews);
    RUN_TEST(test_cert_expires_now_renews);
    RUN_TEST(test_cert_1_day_out_window_1_renews);
    RUN_TEST(test_cert_2_days_out_window_1_skips);
    RUN_TEST(test_large_window_triggers_renewal);
    return UNITY_END();
}
