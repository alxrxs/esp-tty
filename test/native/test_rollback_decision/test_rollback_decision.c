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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pending_verify_returns_mark_valid);
    RUN_TEST(test_valid_returns_noop);
    RUN_TEST(test_new_returns_noop);
    RUN_TEST(test_invalid_returns_noop);
    RUN_TEST(test_aborted_returns_noop);
    RUN_TEST(test_undefined_returns_noop);
    return UNITY_END();
}
