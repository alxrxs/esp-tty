/*
 * ssh_keepalive.c -- SSH-protocol-level keepalive tick logic
 */

#include "ssh_keepalive.h"

void ssh_keepalive_init(ssh_keepalive_t *ka,
                        uint32_t interval_ticks,
                        uint32_t count_max,
                        uint32_t now_ticks)
{
    ka->interval_ticks = interval_ticks;
    ka->count_max      = count_max;
    ka->last_activity  = now_ticks;
    ka->last_send      = now_ticks;
    ka->unanswered     = 0;
}

ssh_ka_action_t ssh_keepalive_tick(ssh_keepalive_t *ka,
                                   uint32_t now_ticks,
                                   bool got_inbound)
{
    if (ka->interval_ticks == 0)
        return SSH_KA_IDLE;

    if (got_inbound) {
        ka->last_activity = now_ticks;
        ka->unanswered    = 0;
        return SSH_KA_IDLE;
    }

    /* Check drop first: if we already hit count_max, keep returning DROP. */
    if (ka->unanswered >= ka->count_max)
        return SSH_KA_DROP;

    /* Time since whichever reference point is more recent: last inbound
     * activity or last sent probe.
     *
     * A plain uint32_t max() comparison fails across the uint32_t wrap-around
     * boundary: a stale pre-wrap value (e.g. 0xFFFF_FF00) is numerically
     * larger than a fresh post-wrap value (e.g. 0x0000_0100) even though the
     * post-wrap value is more recent.
     *
     * Use signed 32-bit subtraction instead: (int32_t)(a - b) < 0 means b is
     * more recent than a (b happened later in the tick sequence).  This is the
     * same approach FreeRTOS uses for timeouts (TIME_AFTER macro). */
    uint32_t ref;
    if ((int32_t)(ka->last_send - ka->last_activity) > 0)
        ref = ka->last_send;      /* last_send is more recent */
    else
        ref = ka->last_activity;  /* last_activity is more recent (or equal) */

    /* Wrapping subtraction handles uint32_t rollover correctly. */
    if ((now_ticks - ref) >= ka->interval_ticks)
        return SSH_KA_SEND;

    return SSH_KA_IDLE;
}

void ssh_keepalive_sent(ssh_keepalive_t *ka, uint32_t now_ticks)
{
    ka->last_send = now_ticks;
    ka->unanswered++;
}
