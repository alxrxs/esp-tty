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

/* --- Large interval (near UINT32_MAX/2) -- must not overflow comparison --- */

void test_ka_large_interval_no_spurious_send(void)
{
    /* interval_ticks = UINT32_MAX/2: only half a wrap should not trigger */
    uint32_t big = 0x7FFFFFFFu;
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, big, 3, 0);

    /* Advance by big-1: just below threshold */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, big - 1, false));
}

void test_ka_large_interval_exact_boundary_sends(void)
{
    uint32_t big = 0x7FFFFFFFu;
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, big, 3, 0);

    /* Exactly at threshold */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, big, false));
}

/* --- Interval == 1 (minimum nonzero): every tick without inbound -> send --- */

void test_ka_interval_one_sends_every_tick(void)
{
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, 1, 10, 0);

    /* tick 1: elapsed=1 >= interval=1 -> SEND */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 1, false));
    ssh_keepalive_sent(&ka, 1);

    /* tick 2: elapsed since last_send=1 is 1 >= 1 -> SEND again */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 2, false));
}

/* --- Monotonic clock skew: now_ticks < last_send (shouldn't happen,
 *     but wrapping arithmetic must handle it without crashing) ---------- */

void test_ka_now_less_than_last_send_no_crash(void)
{
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, 1000, 3, 5000);
    /* Manually set last_send ahead of "now" (simulated skew) */
    ka.last_send = 9000;

    /* now=100, last_send=9000 -> (100 - 9000) wraps to 0xFFFFD8EC which
     * is >> 1000, so it returns SEND.  Just must not crash. */
    ssh_ka_action_t act = ssh_keepalive_tick(&ka, 100, false);
    (void)act;  /* result is implementation-defined for skew; no crash is the goal */
    TEST_ASSERT_TRUE(1);
}

/* --- Retry exhaustion: count_max probes then permanently DROP ------------ */

void test_ka_retry_exhaustion_permanent_drop(void)
{
    /* count_max=5: send 5 probes, then every subsequent tick is DROP */
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, 100, 5, 0);

    for (uint32_t i = 1; i <= 5; i++) {
        ssh_keepalive_sent(&ka, i * 100);
    }
    TEST_ASSERT_EQUAL_UINT32(5, ka.unanswered);

    /* Every future tick must be DROP */
    for (uint32_t t = 1000; t <= 5000; t += 1000) {
        TEST_ASSERT_EQUAL_INT(SSH_KA_DROP,
            ssh_keepalive_tick(&ka, t, false));
    }
}

/* --- Reset-on-traffic: inbound at any point resets unanswered ----------- */

void test_ka_reset_on_traffic_mid_retry(void)
{
    /* Send 2 probes (count_max=3 so not yet at limit), then inbound */
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, 1000, 3, 0);

    ssh_keepalive_sent(&ka, 1000);
    ssh_keepalive_sent(&ka, 2000);
    TEST_ASSERT_EQUAL_UINT32(2, ka.unanswered);

    /* Inbound at tick 2500 resets counter */
    ssh_keepalive_tick(&ka, 2500, true);
    TEST_ASSERT_EQUAL_UINT32(0, ka.unanswered);
    TEST_ASSERT_EQUAL_UINT32(2500, ka.last_activity);
}

/* --- Init sets baseline correctly -------------------------------------- */

void test_ka_init_sets_last_activity_and_send(void)
{
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, 500, 2, 12345);
    TEST_ASSERT_EQUAL_UINT32(12345, ka.last_activity);
    TEST_ASSERT_EQUAL_UINT32(12345, ka.last_send);
    TEST_ASSERT_EQUAL_UINT32(0,     ka.unanswered);
    TEST_ASSERT_EQUAL_UINT32(500,   ka.interval_ticks);
    TEST_ASSERT_EQUAL_UINT32(2,     ka.count_max);
}

/* --- interval==0, inbound does not change disabled state --------------- */

void test_ka_disabled_inbound_still_idle(void)
{
    ssh_keepalive_t ka;
    ssh_keepalive_init(&ka, 0, 3, 0);

    /* Any combination of inbound/no-inbound stays IDLE */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE, ssh_keepalive_tick(&ka, 10000, true));
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE, ssh_keepalive_tick(&ka, 20000, false));
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE, ssh_keepalive_tick(&ka, 30000, true));
}

/* --- Wrapping: last_activity near UINT32_MAX, inbound resets cleanly ---- */

void test_ka_wrap_last_activity_reset(void)
{
    ssh_keepalive_t ka;
    uint32_t near_max = 0xFFFFFF00u;
    ssh_keepalive_init(&ka, 100, 3, near_max);

    /* Inbound at tick 0x10 (after wrap): last_activity = 0x10, unanswered = 0 */
    ssh_keepalive_tick(&ka, 0x10u, true);
    TEST_ASSERT_EQUAL_UINT32(0, ka.unanswered);
    TEST_ASSERT_EQUAL_UINT32(0x10u, ka.last_activity);

    /* last_send is still 0xFFFFFF00 from init (> last_activity 0x10 unsigned),
     * so ref = last_send = 0xFFFFFF00.  To test activity-based timing, explicitly
     * record a send at 0x10 so last_send matches last_activity. */
    ssh_keepalive_sent(&ka, 0x10u);
    ka.unanswered = 0; /* clear the artificial unanswered count */

    /* 99 ticks after send/activity: below threshold -> IDLE */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 0x10u + 99, false));

    /* 100 ticks after send/activity: exactly at threshold -> SEND */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 0x10u + 100, false));
}

/* --- Wrap-around: post-wrap last_activity must beat pre-wrap last_send --
 *
 * Regression test for the uint32_t max() wrap bug.
 *
 * Scenario:
 *   - init at tick 0xFFFF_FF00 (near UINT32_MAX), interval=500
 *   - send probe at 0xFFFF_FF10 -> last_send = 0xFFFF_FF10
 *   - inbound at 0x0000_0050 (after wrap) -> last_activity = 0x0000_0050
 *   - tick at 0x0000_0250 (no inbound)
 *
 * Before the fix:
 *   ref = max(0xFFFF_FF10, 0x0000_0050) = 0xFFFF_FF10  (numerically larger, but older!)
 *   elapsed = 0x0000_0250 - 0xFFFF_FF10 = 0x340 = 832 > 500 -> spurious SEND
 *
 * After the fix (signed comparison):
 *   (int32_t)(0xFFFF_FF10 - 0x0000_0050) = (int32_t)0xFFFF_FEC0 = negative
 *   -> last_activity (0x50) is more recent -> ref = 0x50
 *   elapsed = 0x0000_0250 - 0x0000_0050 = 0x200 = 512 > 500 -> correctly SEND
 *
 * Also verify that at tick 0x0000_0243 (elapsed=499 < 500) -> IDLE,
 * and at tick 0x0000_0244 (elapsed=500 == interval) -> SEND. */
void test_ka_wrap_send_not_before_activity_interval(void)
{
    ssh_keepalive_t ka;
    uint32_t near_max = 0xFFFFFF00u;
    ssh_keepalive_init(&ka, 500, 3, near_max);

    /* Simulate a probe sent before the wrap */
    ssh_keepalive_sent(&ka, 0xFFFFFF10u);
    ka.unanswered = 0;  /* don't want to trigger drop path */

    /* Inbound arrives after the wrap: last_activity = 0x50 */
    ssh_keepalive_tick(&ka, 0x00000050u, true);
    TEST_ASSERT_EQUAL_UINT32(0x00000050u, ka.last_activity);

    /* Tick at 0x243 (499 ticks after last_activity=0x50): below interval -> IDLE */
    TEST_ASSERT_EQUAL_INT(SSH_KA_IDLE,
        ssh_keepalive_tick(&ka, 0x00000243u, false));

    /* Tick at 0x244 (500 ticks after last_activity=0x50): at interval -> SEND */
    TEST_ASSERT_EQUAL_INT(SSH_KA_SEND,
        ssh_keepalive_tick(&ka, 0x00000244u, false));
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
    /* Additional edge cases */
    RUN_TEST(test_ka_large_interval_no_spurious_send);
    RUN_TEST(test_ka_large_interval_exact_boundary_sends);
    RUN_TEST(test_ka_interval_one_sends_every_tick);
    RUN_TEST(test_ka_now_less_than_last_send_no_crash);
    RUN_TEST(test_ka_retry_exhaustion_permanent_drop);
    RUN_TEST(test_ka_reset_on_traffic_mid_retry);
    RUN_TEST(test_ka_init_sets_last_activity_and_send);
    RUN_TEST(test_ka_disabled_inbound_still_idle);
    RUN_TEST(test_ka_wrap_last_activity_reset);
    RUN_TEST(test_ka_wrap_send_not_before_activity_interval);
    return UNITY_END();
}
