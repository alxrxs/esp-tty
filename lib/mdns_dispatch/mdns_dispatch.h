/*
 * mdns_dispatch.h -- one-shot mDNS start-dispatch logic
 *
 * Extracted from wifi.c for unit-testability.  The dispatch gate keeps a
 * static flag so mDNS initialisation fires at most once per boot, regardless
 * of how many IP or Wi-Fi events arrive.
 *
 * The caller supplies a task-create function pointer so tests can inject a
 * stub without linking against FreeRTOS.
 */

#pragma once

#include <stdbool.h>

/*
 * Function type matching xTaskCreate's signature subset used here.
 * Returns 1 (pdPASS) on success, 0 (pdFAIL) on failure.
 */
typedef int (*mdns_task_create_fn)(void);

/*
 * mdns_dispatch_once -- attempt to start mDNS exactly once.
 *
 * On the first call, invokes create_task().  If create_task returns
 * pdPASS (1) the started flag is set permanently.  If it returns any
 * other value, the flag is cleared so the next call will retry.
 *
 * Subsequent calls after a successful dispatch are no-ops.
 *
 * Returns true if mDNS was (or had previously been) dispatched
 * successfully, false otherwise.
 */
bool mdns_dispatch_once(mdns_task_create_fn create_task);

/*
 * mdns_dispatch_reset -- reset internal state (for unit tests only).
 *
 * Resets the one-shot started flag so a fresh dispatch sequence can be
 * tested in the same process.  Not intended for production use.
 */
void mdns_dispatch_reset(void);
