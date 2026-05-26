/*
 * mdns_dispatch.c -- one-shot mDNS start-dispatch logic
 */

#include "mdns_dispatch.h"

#include <stdatomic.h>

#define PDPASS 1

/* Use an atomic bool to prevent concurrent IP_EVENT handlers from racing
 * through the test-then-set and double-dispatching mDNS.  The volatile
 * qualifier alone does not provide the required atomicity guarantee. */
static _Atomic bool s_started = false;

bool mdns_dispatch_once(mdns_task_create_fn create_task)
{
    /* Atomically claim the "started" flag.  If it was already true, this is a
     * no-op and we return true immediately (idempotent after success).
     * If it was false, we set it to true and proceed to dispatch. */
    bool expected = false;
    if (!atomic_compare_exchange_strong(&s_started, &expected, true)) {
        /* Another thread already set it to true -- dispatch was done (or is
         * in progress).  Return true: mDNS is (being) started. */
        return true;
    }

    int ret = create_task();
    if (ret != PDPASS) {
        /* Task creation failed: clear the flag so the next caller will retry. */
        atomic_store(&s_started, false);
        return false;
    }
    return true;
}

void mdns_dispatch_reset(void)
{
    atomic_store(&s_started, false);
}
