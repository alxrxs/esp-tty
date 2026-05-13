/*
 * ssh_keepalive.h -- SSH-protocol-level keepalive tick logic (portable)
 *
 * Pure timing/state logic with no wolfSSH, ESP-IDF, or FreeRTOS deps.
 * The caller provides tick values (e.g. xTaskGetTickCount() cast to uint32_t)
 * and the library decides what action to take.
 *
 * Usage pattern (per pump-loop iteration):
 *
 *   ssh_ka_action_t act = ssh_keepalive_tick(&ka, now_ticks, got_inbound);
 *   if (act == SSH_KA_SEND)   wolfSSH_global_request(...);
 *   if (act == SSH_KA_DROP)   { log + teardown; }
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ticks are abstract 1-ms counts; on FreeRTOS use pdMS_TO_TICKS wrapping.
 * On the native test host use milliseconds directly. */

typedef enum {
    SSH_KA_IDLE = 0, /* nothing to do */
    SSH_KA_SEND,     /* send a keepalive probe now */
    SSH_KA_DROP      /* peer unresponsive -- tear down the session */
} ssh_ka_action_t;

typedef struct {
    uint32_t interval_ticks;  /* ticks between probes (0 = disabled) */
    uint32_t count_max;       /* probes before drop */

    uint32_t last_activity;   /* tick of most-recent inbound data */
    uint32_t last_send;       /* tick of most-recent probe sent */
    uint32_t unanswered;      /* probes sent without an inbound reply */
} ssh_keepalive_t;

/*
 * Initialise state.  interval_ms=0 disables keepalives entirely.
 * now_ticks is the current tick (sets the baseline activity timestamp).
 */
void ssh_keepalive_init(ssh_keepalive_t *ka,
                        uint32_t interval_ms,
                        uint32_t count_max,
                        uint32_t now_ticks);

/*
 * Call once per pump-loop iteration.
 *
 * now_ticks    : current tick count (monotonic, wraps at UINT32_MAX)
 * got_inbound  : true if any inbound data arrived this iteration
 *
 * Returns the action the caller should take.  If SSH_KA_SEND is returned
 * the caller must actually send the probe before calling tick again so
 * that last_send is updated via ssh_keepalive_sent().
 */
ssh_ka_action_t ssh_keepalive_tick(ssh_keepalive_t *ka,
                                   uint32_t now_ticks,
                                   bool got_inbound);

/*
 * Call after successfully sending a probe (when tick returned SSH_KA_SEND).
 * Records the send time and increments the unanswered counter.
 */
void ssh_keepalive_sent(ssh_keepalive_t *ka, uint32_t now_ticks);

#ifdef __cplusplus
}
#endif
