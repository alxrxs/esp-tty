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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pending_verify_returns_mark_valid);
    RUN_TEST(test_valid_returns_noop);
    RUN_TEST(test_new_returns_noop);
    RUN_TEST(test_invalid_returns_noop);
    RUN_TEST(test_aborted_returns_noop);
    RUN_TEST(test_undefined_returns_noop);
    /* New edge-case tests */
    RUN_TEST(test_out_of_range_int_returns_noop);
    RUN_TEST(test_pending_verify_is_distinct_from_zero);
    return UNITY_END();
}
