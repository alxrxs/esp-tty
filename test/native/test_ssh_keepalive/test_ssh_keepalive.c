/*
 * test_ssh_keepalive.c -- unit tests for ssh_keepalive tick logic (native)
 *
 * All timing is driven by explicit tick values so the tests are
 * deterministic with no real-time dependency.
 */

#include <stdint.h>
#include <stdbool.h>

#include "unity.h"
#include "ssh_keepalive.h"

void setUp(void)    {}
void tearDown(void) {}

/* Convenience: interval=1000 ticks, count_max=3, starting at tick 0. */
static ssh_keepalive_t make_ka(uint32_t interval_ticks, uint32_t count_max)
{
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, interval_ticks, count_max, 0);
    return ka;
}

/* --- Disabled (interval=0) ----------------------------------------- */

void test_ka_disabled_always_idle(void)
{
    ssh_keepalive_t ka = make_ka(0, 3);
    /* Far in the future, no inbound -- must stay idle */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 999999, false));
}

void test_ka_disabled_with_inbound_stays_idle(void)
{
    ssh_keepalive_t ka = make_ka(0, 3);
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 5000, true));
}

/* --- No activity, less than interval -------------------------------- */

void test_ka_no_send_before_interval(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);
    /* 999 ticks elapsed -- one short of the threshold */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 999, false));
}

/* --- Exactly at interval -> send ------------------------------------ */

void test_ka_send_at_interval(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 1000, false));
}

void test_ka_send_past_interval(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 5000, false));
}

/* --- Inbound activity resets unanswered counter -------------------- */

void test_ka_inbound_resets_unanswered(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);

    /* Simulate two unanswered probes */
    ssh_keepalive_sent(&ka, 1000);
    ssh_keepalive_sent(&ka, 2000);
    TEST_ASSERT_EQUAL_UINT32(2, ka.unanswered);

    /* Inbound data: counter must be cleared */
    ssh_keepalive_tick(&ka, 2500, true);
    TEST_ASSERT_EQUAL_UINT32(0, ka.unanswered);
}

void test_ka_inbound_resets_activity_timestamp(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);

    /* No inbound for 1200 ticks would normally trigger a send */
    ssh_keepalive_tick(&ka, 500, true); /* inbound at tick 500 */

    /* 900 ticks after the last inbound -- still below interval */
    ssh_ka_action_t act = ssh_keepalive_tick(&ka, 1400, false);
    /* 1400 - 500 = 900 < 1000 -> idle */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE, act);
}

/* --- Reaching count_max -> drop ------------------------------------- */

void test_ka_drop_at_count_max(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);

    /* Simulate count_max probes sent without a reply */
    ssh_keepalive_sent(&ka, 1000);
    ssh_keepalive_sent(&ka, 2000);
    ssh_keepalive_sent(&ka, 3000);
    TEST_ASSERT_EQUAL_UINT32(3, ka.unanswered);

    /* Next tick must return DROP, not SEND */
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP,
        ssh_keepalive_tick(&ka, 9000, false));
}

void test_ka_drop_before_send_when_already_at_max(void)
{
    /* count_max=1: one unanswered probe -> drop on next tick */
    ssh_keepalive_t ka = make_ka(1000, 1);
    ssh_keepalive_sent(&ka, 1000);
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP,
        ssh_keepalive_tick(&ka, 9000, false));
}

/* --- SEND followed by sent() -> next interval resets correctly ------ */

void test_ka_second_probe_after_first(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);

    /* First probe due at tick 1000 */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 1000, false));
    ssh_keepalive_sent(&ka, 1000);
    TEST_ASSERT_EQUAL_UINT32(1, ka.unanswered);

    /* Tick at 1999 -- interval not yet elapsed since last send */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 1999, false));

    /* Tick at 2000 -- exactly one interval since last send */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 2000, false));
}

/* --- Tick overflow (uint32_t wrap) ---------------------------------- */

void test_ka_tick_wrap_triggers_send(void)
{
    ssh_keepalive_t ka;
    /* Start near UINT32_MAX */
    uint32_t start = 0xFFFFFF00u;
    ssh_keepalive_init(&ka, 100, 3, start);

    /* Wrap to 0x63 (start + 0x163 wrapped) */
    uint32_t now = 0x00000063u; /* 0xFFFFFF00 + 0x163 = 0x100000063 -> 0x63 mod 2^32 */
    /* elapsed = 0x63 - 0xFFFFFF00 mod 2^32 = 0x163 = 355 > 100 */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, now, false));
}

/* --- Inbound immediately after init -> idle, no send yet ------------------ */

void test_ka_inbound_before_interval_stays_idle(void)
{
    ssh_keepalive_t ka = make_ka(1000, 3);

    /* Inbound at tick 500 -- well before interval, reset activity */
    ssh_ka_action_t act = ssh_keepalive_tick(&ka, 500, true);
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE, act);
    TEST_ASSERT_EQUAL_UINT32(0, ka.unanswered);  /* inbound cleared any counter */
}

/* --- ssh_keepalive_sent increments unanswered monotonically --------------- */

void test_ka_sent_increments_unanswered(void)
{
    ssh_keepalive_t ka = make_ka(1000, 10);
    TEST_ASSERT_EQUAL_UINT32(0, ka.unanswered);

    ssh_keepalive_sent(&ka, 1000);
    TEST_ASSERT_EQUAL_UINT32(1, ka.unanswered);

    ssh_keepalive_sent(&ka, 2000);
    TEST_ASSERT_EQUAL_UINT32(2, ka.unanswered);

    ssh_keepalive_sent(&ka, 3000);
    TEST_ASSERT_EQUAL_UINT32(3, ka.unanswered);
}

/* --- DROP is sticky: once count_max hit, all subsequent ticks return DROP -- */

void test_ka_drop_is_sticky_after_count_max(void)
{
    ssh_keepalive_t ka = make_ka(1000, 2);

    ssh_keepalive_sent(&ka, 1000);
    ssh_keepalive_sent(&ka, 2000);  /* unanswered == count_max == 2 */

    /* Multiple ticks at far future -- all must return DROP, never SEND */
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP, ssh_keepalive_tick(&ka, 5000, false));
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP, ssh_keepalive_tick(&ka, 6000, false));
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP, ssh_keepalive_tick(&ka, 9999, false));
}

/* --- After DROP, inbound resets counter and resumes normal behaviour ------- */

void test_ka_inbound_after_drop_resets_and_resumes(void)
{
    ssh_keepalive_t ka = make_ka(1000, 2);

    /* Exhaust budget */
    ssh_keepalive_sent(&ka, 1000);
    ssh_keepalive_sent(&ka, 2000);
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP, ssh_keepalive_tick(&ka, 5000, false));

    /* Inbound: resets the counter and last_activity timestamp */
    ssh_keepalive_tick(&ka, 6000, true);
    TEST_ASSERT_EQUAL_UINT32(0, ka.unanswered);

    /* 900 ticks after inbound: still idle (below interval) */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 6900, false));

    /* 1000 ticks after inbound: must send again */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 7000, false));
}

/* --- count_max == 0: "unanswered >= count_max" is immediately true (0 >= 0)
 *     so the first tick with no inbound returns DROP.  This is a degenerate
 *     configuration: zero tolerance means instant drop.  Document this. ------- */

void test_ka_count_max_zero_drops_immediately(void)
{
    /* With count_max == 0:
     *   unanswered (0) >= count_max (0)  ->  DROP on every tick with no inbound.
     * This is a documented corner case of the implementation. */
    ssh_keepalive_t ka = make_ka(1000, 0);

    /* Even at tick 1 (before any interval has elapsed) we get DROP. */
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP,
        ssh_keepalive_tick(&ka, 1, false));

    /* Inbound resets unanswered to 0, but then the very next tick still DROPs
     * because 0 >= 0. */
    ssh_keepalive_tick(&ka, 500, true);   /* inbound: unanswered = 0 */
    TEST_ASSERT_EQUAL_INT(SSH_KA_DROP,
        ssh_keepalive_tick(&ka, 2000, false));
}

/* ------------------------------------------------------------------ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ka_disabled_always_idle);
    RUN_TEST(test_ka_disabled_with_inbound_stays_idle);
    RUN_TEST(test_ka_no_send_before_interval);
    RUN_TEST(test_ka_send_at_interval);
    RUN_TEST(test_ka_send_past_interval);
    RUN_TEST(test_ka_inbound_resets_unanswered);
    RUN_TEST(test_ka_inbound_resets_activity_timestamp);
    RUN_TEST(test_ka_drop_at_count_max);
    RUN_TEST(test_ka_drop_before_send_when_already_at_max);
    RUN_TEST(test_ka_second_probe_after_first);
    RUN_TEST(test_ka_tick_wrap_triggers_send);
    /* New edge-case tests */
    RUN_TEST(test_ka_inbound_before_interval_stays_idle);
    RUN_TEST(test_ka_sent_increments_unanswered);
    RUN_TEST(test_ka_drop_is_sticky_after_count_max);
    RUN_TEST(test_ka_inbound_after_drop_resets_and_resumes);
    RUN_TEST(test_ka_count_max_zero_drops_immediately);
    return UNITY_END();
}
