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

/* NEW image (not yet pending) -> no-op */
void test_new_returns_noop(void)
{
    TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP,
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

/* Only PENDING_VERIFY is MARK_VALID -- enum constants have the right values. */
void test_enum_values_match_esp_idf_spec(void)
{
    TEST_ASSERT_EQUAL_INT(0x0,        (int)ESP_OTA_IMG_NEW);
    TEST_ASSERT_EQUAL_INT(0x1,        (int)ESP_OTA_IMG_PENDING_VERIFY);
    TEST_ASSERT_EQUAL_INT(0x2,        (int)ESP_OTA_IMG_VALID);
    TEST_ASSERT_EQUAL_INT(0x3,        (int)ESP_OTA_IMG_INVALID);
    TEST_ASSERT_EQUAL_INT(0x4,        (int)ESP_OTA_IMG_ABORTED);
    TEST_ASSERT_EQUAL_INT((int)0xFFFFFFFF, (int)ESP_OTA_IMG_UNDEFINED);
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

/* Every non-PENDING_VERIFY value produces NOOP -- confirm no false positives. */
void test_all_non_pending_states_are_noop(void)
{
    esp_ota_img_states_t states[] = {
        ESP_OTA_IMG_NEW,
        ESP_OTA_IMG_VALID,
        ESP_OTA_IMG_INVALID,
        ESP_OTA_IMG_ABORTED,
        ESP_OTA_IMG_UNDEFINED,
    };
    for (int i = 0; i < (int)(sizeof(states)/sizeof(states[0])); i++) {
        TEST_ASSERT_EQUAL_INT(ROLLBACK_DECISION_NOOP, rollback_decide(states[i]));
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pending_verify_returns_mark_valid);
    RUN_TEST(test_valid_returns_noop);
    RUN_TEST(test_new_returns_noop);
    RUN_TEST(test_invalid_returns_noop);
    RUN_TEST(test_aborted_returns_noop);
    RUN_TEST(test_undefined_returns_noop);
    RUN_TEST(test_out_of_range_int_returns_noop);
    RUN_TEST(test_pending_verify_is_distinct_from_zero);
    /* Additional boundary / regression cases */
    RUN_TEST(test_enum_values_match_esp_idf_spec);
    RUN_TEST(test_valid_not_equal_pending_verify);
    RUN_TEST(test_pending_verify_idempotent);
    RUN_TEST(test_all_non_pending_states_are_noop);
    return UNITY_END();
}
