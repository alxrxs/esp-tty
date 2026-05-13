/*
 * ssh_keepalive.c -- SSH-protocol-level keepalive tick logic
 */

#include "ssh_keepalive.h"

void ssh_keepalive_init(ssh_keepalive_t *ka,
                        uint32_t interval_ms,
                        uint32_t count_max,
                        uint32_t now_ticks)
{
    ka->interval_ticks = interval_ms;   /* caller converts ms->ticks; we store as-is */
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

    /* Time since last inbound activity or last sent probe, whichever is later. */
    uint32_t ref = (ka->last_send > ka->last_activity)
                   ? ka->last_send : ka->last_activity;

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
