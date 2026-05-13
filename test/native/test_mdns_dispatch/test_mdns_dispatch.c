/*
 * test_mdns_dispatch.c -- unit tests for mdns_dispatch_once()
 *
 * Tests the one-shot dispatch gate: idempotency on success, retry on
 * task-creation failure.
 */

#include "unity.h"
#include "mdns_dispatch.h"

void setUp(void)    { mdns_dispatch_reset(); }
void tearDown(void) {}

/* Stub task creators ---------------------------------------------------- */

static int stub_create_ok(void)  { return 1; }  /* pdPASS */
static int stub_create_fail(void) { return 0; }  /* pdFAIL */

static int g_call_count;
static int stub_count_calls(void) { g_call_count++; return 1; }

/* Tests ------------------------------------------------------------------ */

/*
 * First call with a succeeding task creator returns true.
 */
void test_first_call_dispatches(void)
{
    bool result = mdns_dispatch_once(stub_create_ok);
    TEST_ASSERT_TRUE(result);
}

/*
 * Second call after a successful dispatch is a no-op (create_task not called
 * again) and returns true.
 */
void test_second_call_is_noop_after_success(void)
{
    mdns_dispatch_once(stub_create_ok);

    g_call_count = 0;
    bool result = mdns_dispatch_once(stub_count_calls);
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_EQUAL_INT(0, g_call_count);
}

/*
 * Many repeated calls after success all return true and never invoke
 * create_task again.
 */
void test_repeated_calls_after_success_are_noop(void)
{
    mdns_dispatch_once(stub_create_ok);

    g_call_count = 0;
    for (int i = 0; i < 10; i++) {
        bool r = mdns_dispatch_once(stub_count_calls);
        TEST_ASSERT_TRUE(r);
    }
    TEST_ASSERT_EQUAL_INT(0, g_call_count);
}

/*
 * When task creation fails, dispatch_once returns false.
 */
void test_task_create_failure_returns_false(void)
{
    bool result = mdns_dispatch_once(stub_create_fail);
    TEST_ASSERT_FALSE(result);
}

/*
 * When task creation fails, the one-shot flag is reset so the next call
 * will try again (retry semantics).
 */
void test_task_create_failure_allows_retry(void)
{
    mdns_dispatch_once(stub_create_fail);

    g_call_count = 0;
    bool result = mdns_dispatch_once(stub_count_calls);
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_EQUAL_INT(1, g_call_count);
}

/*
 * Fail, fail, succeed: each failure resets the flag; the third call
 * succeeds and subsequent calls are no-ops.
 */
void test_fail_fail_succeed_then_noop(void)
{
    TEST_ASSERT_FALSE(mdns_dispatch_once(stub_create_fail));
    TEST_ASSERT_FALSE(mdns_dispatch_once(stub_create_fail));

    TEST_ASSERT_TRUE(mdns_dispatch_once(stub_create_ok));

    g_call_count = 0;
    TEST_ASSERT_TRUE(mdns_dispatch_once(stub_count_calls));
    TEST_ASSERT_EQUAL_INT(0, g_call_count);
}

/* ------------------------------------------------------------------ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_first_call_dispatches);
    RUN_TEST(test_second_call_is_noop_after_success);
    RUN_TEST(test_repeated_calls_after_success_are_noop);
    RUN_TEST(test_task_create_failure_returns_false);
    RUN_TEST(test_task_create_failure_allows_retry);
    RUN_TEST(test_fail_fail_succeed_then_noop);
    return UNITY_END();
}
