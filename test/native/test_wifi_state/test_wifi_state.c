/*
 * test_wifi_state.c -- unit tests for wifi_decide_next_step()
 *
 * Tests the pure decision function extracted from wifi_init_smart().
 * No ESP-IDF, FreeRTOS, or hardware dependencies; compiled for the native
 * host target under PlatformIO.
 *
 * The full ESP-IDF driver lifecycle (esp_wifi_init, event groups, SNTP,
 * SCEP enroll, esp_restart) is tested on-device only -- it cannot be
 * meaningfully mocked at the native layer without rebuilding half of
 * ESP-IDF.  wifi_decide_next_step() is the testable unit because all of
 * the branching logic lives there.
 *
 * Truth table covered (rows numbered as in the spec):
 *
 *  #  | no_ntp | cert | expired | synced | ntp_req | attempts | retry_max | expected
 *  ---|--------|------|---------|--------|---------|----------|-----------|----------
 *  1  |   no   |  no  |    -    |   no   |   no    |    0     |     5     | BOOTSTRAP_FULL
 *  2  |   no   | yes  |   no    |  yes   |   no    |    0     |     5     | ENTERPRISE
 *  3  |   no   | yes  |   no    |   no   |   yes   |    0     |     5     | BOOTSTRAP_NTP_ONLY
 *  4  |   no   | yes  |   no    |  yes   |   yes   |    0     |     5     | ENTERPRISE
 *  5  |   no   | yes  |  yes    |  yes   |   no    |    0     |     5     | BOOTSTRAP_FULL
 *  6  |   no   | yes  |   no    |  yes   |   no    |    3     |     5     | ENTERPRISE  (3 < 5)
 *  7  |   no   | yes  |   no    |  yes   |   no    |    5     |     5     | BOOTSTRAP_FULL (5 >= 5)
 *
 * Additional edge-case rows:
 *  8  |   no   |  no  |    -    |  yes   |   yes   |    0     |     5     | BOOTSTRAP_FULL (no cert wins)
 *  9  |   no   | yes  |   no    |   no   |   no    |    0     |     5     | ENTERPRISE (no ntp req)
 * 10  |   no   | yes  |   no    |  yes   |   no    |    0     |     0     | ENTERPRISE (unlimited retries)
 * 11  |   no   | yes  |   no    |  yes   |   no    |  100     |     0     | ENTERPRISE (unlimited retries)
 * 12  |   no   | yes  |  yes    |   no   |   yes   |    0     |     5     | BOOTSTRAP_FULL (expired wins)
 * 13  |   no   | yes  |   no    |   no   |   yes   |    4     |     5     | BOOTSTRAP_NTP_ONLY (4<5, no time)
 * 14  |   no   | yes  |   no    |  yes   |   no    |    1     |     1     | BOOTSTRAP_FULL (1 >= 1)
 *
 * no-NTP mode rows (no_ntp=true overrides everything):
 * 15  |  yes   | yes  |   no    |  yes   |   no    |    0     |     5     | BOOTSTRAP_FULL (cert present, no_ntp wins)
 * 16  |  yes   |  no  |    -    |   no   |   no    |    0     |     5     | BOOTSTRAP_FULL (no cert, no_ntp wins)
 * 17  |  yes   | yes  |  yes    |  yes   |   no    |    0     |     5     | BOOTSTRAP_FULL (cert expired, no_ntp wins)
 * 18  |  yes   | yes  |   no    |  yes   |  yes    |    0     |     5     | BOOTSTRAP_FULL (ntp_req set, no_ntp still wins)
 */

#include "unity.h"
#include "wifi_state.h"

void setUp(void)    {}
void tearDown(void) {}

/* Helper: call wifi_decide_next_step with no_ntp_mode=false (normal mode).
 * All existing tests use this wrapper so they don't need to be rewritten
 * when the no_ntp_mode parameter was added. */
static wifi_decision_t decide(bool cert_present, bool cert_expired,
                               bool ntp_synced, bool ntp_req,
                               int attempts, int retry_max)
{
    return wifi_decide_next_step(cert_present, cert_expired, ntp_synced,
                                 ntp_req, false /* no_ntp_mode */,
                                 attempts, retry_max);
}

/* --- Row 1: No cert -> BOOTSTRAP_FULL regardless of other flags ---------- */
void test_no_cert_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(false, false, false, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 2: Cert present, not expired, NTP not required -> ENTERPRISE ---- */
void test_cert_valid_no_ntp_requirement_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 3: Cert valid, NTP required, NOT yet synced -> BOOTSTRAP_NTP_ONLY */
void test_cert_valid_ntp_required_not_synced_returns_bootstrap_ntp_only(void)
{
    wifi_decision_t d = decide(true, false, false, true, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_NTP_ONLY, d);
}

/* --- Row 4: Cert valid, NTP required, ALREADY synced -> ENTERPRISE -------- */
void test_cert_valid_ntp_required_synced_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, true, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 5: Cert expired -> BOOTSTRAP_FULL -------------------------------- */
void test_cert_expired_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(true, true, true, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 6: Cert valid, enterprise tried 3 times (< max=5) -> ENTERPRISE -- */
void test_enterprise_attempts_below_max_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, false, 3, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 7: Cert valid, enterprise attempts == max -> BOOTSTRAP_FULL ------- */
void test_enterprise_attempts_at_max_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(true, false, true, false, 5, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 8: No cert, even with NTP flag set and synced -> BOOTSTRAP_FULL -- */
void test_no_cert_ntp_flags_set_still_bootstrap_full(void)
{
    wifi_decision_t d = decide(false, false, true, true, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 9: Cert valid, NTP not required, clock unsynced -> ENTERPRISE ----- */
void test_cert_valid_ntp_not_required_unsynced_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, false, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 10: Unlimited retries (max=0), 0 attempts -> ENTERPRISE ---------- */
void test_unlimited_retries_zero_attempts_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, false, 0, 0);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 11: Unlimited retries (max=0), 100 attempts -> ENTERPRISE -------- */
void test_unlimited_retries_many_attempts_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, false, 100, 0);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 12: Cert expired, NTP not synced, NTP required -> BOOTSTRAP_FULL - */
void test_cert_expired_ntp_flags_set_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(true, true, false, true, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 13: Cert valid, 4 attempts < max=5, NTP req, no sync -> BOOTSTRAP_NTP_ONLY */
void test_cert_valid_attempts_below_max_ntp_required_unsynced(void)
{
    wifi_decision_t d = decide(true, false, false, true, 4, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_NTP_ONLY, d);
}

/* --- Row 14: Cert valid, 1 attempt, max=1 -> BOOTSTRAP_FULL (budget exhausted) */
void test_enterprise_attempts_exactly_one_at_max_one(void)
{
    wifi_decision_t d = decide(true, false, true, false, 1, 1);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- enterprise_attempts > max also triggers BOOTSTRAP_FULL (off-by-one safe) */
void test_enterprise_attempts_exceeds_max_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(true, false, true, false, 7, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Expired cert with unlimited retries still -> BOOTSTRAP_FULL ---------- */
void test_cert_expired_unlimited_retries_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(true, true, true, false, 0, 0);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- No cert, unsynced, NTP required, attempts==max -> BOOTSTRAP_FULL ----- */
void test_no_cert_attempts_at_max_returns_bootstrap_full(void)
{
    wifi_decision_t d = decide(false, false, false, true, 5, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* ==========================================================================
 * no-NTP mode tests (SCEP_NO_NTP_USE_ISSUANCE_TIME)
 *
 * When no_ntp_mode=true, wifi_decide_next_step() must always return
 * BOOTSTRAP_FULL regardless of cert_present, cert_expired, ntp_synced, or
 * ntp_before_eaptls_required.
 * ========================================================================== */

/* --- Row 15: no_ntp=true, cert present and valid -> BOOTSTRAP_FULL --------- */
void test_no_ntp_mode_overrides_valid_cert(void)
{
    wifi_decision_t d = wifi_decide_next_step(
        true,  /* cert_present */
        false, /* cert_expired */
        true,  /* ntp_synced */
        false, /* ntp_before_eaptls_required */
        true,  /* no_ntp_mode */
        0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 16: no_ntp=true, no cert stored -> BOOTSTRAP_FULL (trivially) ----- */
void test_no_ntp_mode_no_cert_bootstrap_full(void)
{
    wifi_decision_t d = wifi_decide_next_step(
        false, /* cert_present */
        false, /* cert_expired */
        false, /* ntp_synced */
        false, /* ntp_before_eaptls_required */
        true,  /* no_ntp_mode */
        0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 17: no_ntp=true, cert expired -> BOOTSTRAP_FULL (no_ntp still wins) */
void test_no_ntp_mode_expired_cert_bootstrap_full(void)
{
    wifi_decision_t d = wifi_decide_next_step(
        true,  /* cert_present */
        true,  /* cert_expired */
        true,  /* ntp_synced */
        false, /* ntp_before_eaptls_required */
        true,  /* no_ntp_mode */
        0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Row 18: no_ntp=true, ntp_req also set -> BOOTSTRAP_FULL (not NTP_ONLY) */
void test_no_ntp_mode_with_ntp_req_still_bootstrap_full(void)
{
    /* If no_ntp_mode and ntp_before_eaptls_required are both true, the
     * no_ntp_mode rule takes precedence and returns BOOTSTRAP_FULL (not
     * BOOTSTRAP_NTP_ONLY).  In practice both flags should never both be set
     * (the build #errors out), but the logic is tested here to confirm
     * Rule 0 runs before Rule 4. */
    wifi_decision_t d = wifi_decide_next_step(
        true,  /* cert_present */
        false, /* cert_expired */
        true,  /* ntp_synced */
        true,  /* ntp_before_eaptls_required */
        true,  /* no_ntp_mode */
        0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- enterprise_attempts negative (-1): signed int < retry_max -> ENTERPRISE */
void test_enterprise_attempts_negative_is_below_max(void)
{
    /* The parameter is typed int; -1 < 5, so rule 3 doesn't fire. */
    wifi_decision_t d = decide(true, false, true, false, -1, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- enterprise_attempts negative with retry_max == 0: 0 > 0 is false ->
 *     skip rule 3 entirely -> ENTERPRISE.                                --- */
void test_enterprise_attempts_negative_unlimited_retries(void)
{
    wifi_decision_t d = decide(true, false, true, false, -1, 0);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- NTP required but retry budget is exhausted: BOOTSTRAP_FULL wins -------- */
void test_enterprise_at_max_overrides_ntp_only(void)
{
    /* Even though NTP is required and not synced (which normally gives
     * BOOTSTRAP_NTP_ONLY), an exhausted retry budget takes priority (rule 3
     * runs before rule 4). */
    wifi_decision_t d = decide(true, false, false, true, 5, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Cert present, expired, no_ntp_mode=false -> BOOTSTRAP_FULL despite
 *     ntp_required=false and ntp_synced=false                            --- */
void test_cert_expired_regardless_of_ntp_state(void)
{
    wifi_decision_t d = decide(true, true, false, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* ==========================================================================
 * Mode B+ (WIFI_USE_ENTERPRISE + WIFI_ENTERPRISE_SSID) decision scenarios.
 *
 * In Mode B+ the caller always passes cert_present=true and cert_expired=false
 * (embedded certs never "expire" from the decision function's perspective -- a
 * real cert may be stale but there is no SCEP renewer, so we always attempt
 * enterprise).  The only interesting branch is NTP_BEFORE_EAPTLS.
 *
 * Truth table rows for Mode B+:
 *
 *  # | cert | expired | synced | ntp_req | attempts | max | expected
 *  --|------|---------|--------|---------|----------|-----|----------
 * 19 | yes  |   no    |  yes   |   no    |    0     |  5  | ENTERPRISE (normal, clock ok)
 * 20 | yes  |   no    |   no   |   yes   |    0     |  5  | BOOTSTRAP_NTP_ONLY (clock unsynced, NTP required)
 * 21 | yes  |   no    |  yes   |   yes   |    0     |  5  | ENTERPRISE (NTP required, already synced)
 * 22 | yes  |   no    |   no   |   no    |    0     |  5  | ENTERPRISE (NTP not required, skip bootstrap)
 * 23 | yes  |   no    |  yes   |   no    |    5     |  5  | BOOTSTRAP_FULL (budget exhausted; caller ignores and goes to enterprise)
 * ========================================================================== */

/* --- Row 19: Mode B+ normal path (synced, no NTP requirement) ------------- */
void test_modebp_synced_no_ntp_req_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 20: Mode B+ unsynced clock, NTP required -> BOOTSTRAP_NTP_ONLY --- */
void test_modebp_unsynced_ntp_req_returns_bootstrap_ntp_only(void)
{
    wifi_decision_t d = decide(true, false, false, true, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_NTP_ONLY, d);
}

/* --- Row 21: Mode B+ already synced, NTP required -> ENTERPRISE ----------- */
void test_modebp_synced_ntp_req_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, true, true, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 22: Mode B+ unsynced but NTP not required -> ENTERPRISE directly - */
void test_modebp_unsynced_no_ntp_req_returns_enterprise(void)
{
    wifi_decision_t d = decide(true, false, false, false, 0, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_ENTERPRISE, d);
}

/* --- Row 23: Mode B+ budget exhausted -> BOOTSTRAP_FULL (caller maps to enterprise) */
void test_modebp_budget_exhausted_returns_bootstrap_full(void)
{
    /* The decision function returns BOOTSTRAP_FULL when the enterprise retry
     * budget is exhausted.  In Mode B+ wifi_init_enterprise_bootstrap()
     * treats this as "proceed to enterprise anyway" since re-enrollment is
     * not available.  The decision function itself is unaware of Mode B+ --
     * it just applies rule 3.  This test confirms rule 3 still fires. */
    wifi_decision_t d = decide(true, false, true, false, 5, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* --- Mode B+ with ntp_req, unsynced, budget partially used -> NTP_ONLY ---- */
void test_modebp_partial_budget_ntp_req_unsynced_returns_ntp_only(void)
{
    /* 3 attempts out of 5, NTP required but not synced: NTP_ONLY (not FULL). */
    wifi_decision_t d = decide(true, false, false, true, 3, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_NTP_ONLY, d);
}

/* --- Mode B+ budget exhausted AND ntp required AND unsynced: FULL wins ----- */
void test_modebp_budget_exhausted_overrides_ntp_only(void)
{
    /* Rule 3 (attempts >= max) fires before rule 4 (NTP required). */
    wifi_decision_t d = decide(true, false, false, true, 5, 5);
    TEST_ASSERT_EQUAL_INT(WIFI_DECISION_BOOTSTRAP_FULL, d);
}

/* -------------------------------------------------------------------------- */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_no_cert_returns_bootstrap_full);
    RUN_TEST(test_cert_valid_no_ntp_requirement_returns_enterprise);
    RUN_TEST(test_cert_valid_ntp_required_not_synced_returns_bootstrap_ntp_only);
    RUN_TEST(test_cert_valid_ntp_required_synced_returns_enterprise);
    RUN_TEST(test_cert_expired_returns_bootstrap_full);
    RUN_TEST(test_enterprise_attempts_below_max_returns_enterprise);
    RUN_TEST(test_enterprise_attempts_at_max_returns_bootstrap_full);
    RUN_TEST(test_no_cert_ntp_flags_set_still_bootstrap_full);
    RUN_TEST(test_cert_valid_ntp_not_required_unsynced_returns_enterprise);
    RUN_TEST(test_unlimited_retries_zero_attempts_returns_enterprise);
    RUN_TEST(test_unlimited_retries_many_attempts_returns_enterprise);
    RUN_TEST(test_cert_expired_ntp_flags_set_returns_bootstrap_full);
    RUN_TEST(test_cert_valid_attempts_below_max_ntp_required_unsynced);
    RUN_TEST(test_enterprise_attempts_exactly_one_at_max_one);
    RUN_TEST(test_enterprise_attempts_exceeds_max_returns_bootstrap_full);
    RUN_TEST(test_cert_expired_unlimited_retries_returns_bootstrap_full);
    RUN_TEST(test_no_cert_attempts_at_max_returns_bootstrap_full);
    /* no-NTP mode tests */
    RUN_TEST(test_no_ntp_mode_overrides_valid_cert);
    RUN_TEST(test_no_ntp_mode_no_cert_bootstrap_full);
    RUN_TEST(test_no_ntp_mode_expired_cert_bootstrap_full);
    RUN_TEST(test_no_ntp_mode_with_ntp_req_still_bootstrap_full);
    /* New edge-case tests */
    RUN_TEST(test_enterprise_attempts_negative_is_below_max);
    RUN_TEST(test_enterprise_attempts_negative_unlimited_retries);
    RUN_TEST(test_enterprise_at_max_overrides_ntp_only);
    RUN_TEST(test_cert_expired_regardless_of_ntp_state);
    /* Mode B+ decision scenarios */
    RUN_TEST(test_modebp_synced_no_ntp_req_returns_enterprise);
    RUN_TEST(test_modebp_unsynced_ntp_req_returns_bootstrap_ntp_only);
    RUN_TEST(test_modebp_synced_ntp_req_returns_enterprise);
    RUN_TEST(test_modebp_unsynced_no_ntp_req_returns_enterprise);
    RUN_TEST(test_modebp_budget_exhausted_returns_bootstrap_full);
    RUN_TEST(test_modebp_partial_budget_ntp_req_unsynced_returns_ntp_only);
    RUN_TEST(test_modebp_budget_exhausted_overrides_ntp_only);
    return UNITY_END();
}
