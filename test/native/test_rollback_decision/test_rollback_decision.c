/*
 * test_rollback_decision.c -- unit tests for rollback_decide()
 *
 * Tests the pure decision function without any ESP-IDF or FreeRTOS dependency.
 * Compiled with -DROLLBACK_DECISION_NATIVE_TEST which supplies stub enum values.
 */

#include "unity.h"
#include "rollback_decision.h"

void setUp(void)    {}
void tearDown(void) {}

/* PENDING_VERIFY -> must mark valid */
void test_pending_verify_returns_mark_valid(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_MARK_VALID,
                          rollback_decide(ESP_OTA_IMG_PENDING_VERIFY));
}

/* Already VALID -> no-op */
void test_valid_returns_noop(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP,
                          rollback_decide(ESP_OTA_IMG_VALID));
}

/* NEW image -- bootloader has not yet received mark-valid; treat same as
 * PENDING_VERIFY to prevent unexpected rollback if the app crashes later. */
void test_new_returns_mark_valid(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_MARK_VALID,
                          rollback_decide(ESP_OTA_IMG_NEW));
}

/* INVALID -> no-op (shouldn't happen at runtime but must be safe) */
void test_invalid_returns_noop(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP,
                          rollback_decide(ESP_OTA_IMG_INVALID));
}

/* ABORTED -> no-op */
void test_aborted_returns_noop(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP,
                          rollback_decide(ESP_OTA_IMG_ABORTED));
}

/* UNDEFINED -> no-op */
void test_undefined_returns_noop(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP,
                          rollback_decide(ESP_OTA_IMG_UNDEFINED));
}

/* PENDING_VERIFY == MARK_VALID; all other states noop -- explicit out-of-range
 * integer value to confirm no accidental match. */
void test_out_of_range_int_returns_noop(void)
{
    /* Cast an out-of-range integer to the enum type; must not match PENDING_VERIFY. */
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP,
                          rollback_decide((esp_ota_img_states_t)99));
}

/* PENDING_VERIFY is the only state that produces MARK_VALID -- verify the
 * constant itself hasn't been inadvertently changed to 0 (which would collide
 * with the normal "first valid state"). */
void test_pending_verify_is_distinct_from_zero(void)
{
    /* If ESP_OTA_IMG_PENDING_VERIFY were 0, any zeroed memory would trigger
     * MARK_VALID on boot.  This is a defensive consistency check. */
    TEST_ASSERT_NOT_EQUAL(0, (int)ESP_OTA_IMG_PENDING_VERIFY);
}

/*
 * Verify that the test-stub enum values match the REAL ESP-IDF constants from
 * components/app_update/include/esp_ota_ops.h (ESP-IDF 5.x/6.x).
 *
 * Expected values are HARDCODED integer literals here.  If the stub enum in
 * rollback_decision.h drifts from these literals the test fails.  This breaks
 * the circularity: previously the test asserted the stub against itself.
 *
 * ESP-IDF source reference (esp_ota_ops.h):
 *   ESP_OTA_IMG_NEW            = 0x0
 *   ESP_OTA_IMG_PENDING_VERIFY = 0x1
 *   ESP_OTA_IMG_VALID          = 0x2
 *   ESP_OTA_IMG_INVALID        = 0x3
 *   ESP_OTA_IMG_ABORTED        = 0x4
 *   ESP_OTA_IMG_UNDEFINED      = 0xFFFFFFFF
 */
void test_stub_enum_values_match_idf_5x_header(void)
{
    /* Each comparison is: (literal from IDF header) == (stub enum value).
     * If either drifts, the test fails. */
    TEST_ASSERT_EQUAL_INT(0,          (int)ESP_OTA_IMG_NEW);
    TEST_ASSERT_EQUAL_INT(1,          (int)ESP_OTA_IMG_PENDING_VERIFY);
    TEST_ASSERT_EQUAL_INT(2,          (int)ESP_OTA_IMG_VALID);
    TEST_ASSERT_EQUAL_INT(3,          (int)ESP_OTA_IMG_INVALID);
    TEST_ASSERT_EQUAL_INT(4,          (int)ESP_OTA_IMG_ABORTED);
    TEST_ASSERT_EQUAL_INT(-1,         (int)ESP_OTA_IMG_UNDEFINED); /* 0xFFFFFFFF as int */
}

/* VALID does NOT accidentally equal PENDING_VERIFY. */
void test_valid_not_equal_pending_verify(void)
{
    TEST_ASSERT_NOT_EQUAL((int)ESP_OTA_IMG_PENDING_VERIFY,
                          (int)ESP_OTA_IMG_VALID);
}

/* Calling twice with PENDING_VERIFY always gives MARK_VALID (pure function). */
void test_pending_verify_idempotent(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_MARK_VALID,
                          rollback_decide(ESP_OTA_IMG_PENDING_VERIFY));
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_MARK_VALID,
                          rollback_decide(ESP_OTA_IMG_PENDING_VERIFY));
}

/* VALID, INVALID, ABORTED, UNDEFINED produce NOOP.
 * NEW and PENDING_VERIFY produce MARK_VALID. */
void test_mark_valid_states(void)
{
    esp_ota_img_states_t mark_valid_states[] = {
        ESP_OTA_IMG_NEW,
        ESP_OTA_IMG_PENDING_VERIFY,
    };
    for (int i = 0; i < (int)(sizeof(mark_valid_states)/sizeof(mark_valid_states[0])); i++) {
        TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_MARK_VALID,
                              rollback_decide(mark_valid_states[i]));
    }
}

void test_noop_states_are_noop(void)
{
    esp_ota_img_states_t noop_states[] = {
        ESP_OTA_IMG_VALID,
        ESP_OTA_IMG_INVALID,
        ESP_OTA_IMG_ABORTED,
        ESP_OTA_IMG_UNDEFINED,
    };
    for (int i = 0; i < (int)(sizeof(noop_states)/sizeof(noop_states[0])); i++) {
        TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP, rollback_decide(noop_states[i]));
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pending_verify_returns_mark_valid);
    RUN_TEST(test_valid_returns_noop);
    RUN_TEST(test_new_returns_mark_valid);
    RUN_TEST(test_invalid_returns_noop);
    RUN_TEST(test_aborted_returns_noop);
    RUN_TEST(test_undefined_returns_noop);
    RUN_TEST(test_out_of_range_int_returns_noop);
    RUN_TEST(test_pending_verify_is_distinct_from_zero);
    /* Additional boundary / regression cases */
    RUN_TEST(test_stub_enum_values_match_idf_5x_header);
    RUN_TEST(test_valid_not_equal_pending_verify);
    RUN_TEST(test_pending_verify_idempotent);
    RUN_TEST(test_mark_valid_states);
    RUN_TEST(test_noop_states_are_noop);
    return UNITY_END();
}
