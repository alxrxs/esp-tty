/*
 * mdns_dispatch.c -- one-shot mDNS start-dispatch logic
 */

#include "mdns_dispatch.h"

#define PDPASS 1

static volatile bool s_started = false;

bool mdns_dispatch_once(mdns_task_create_fn create_task)
{
    if (s_started) return true;
    s_started = true;

    int ret = create_task();
    if (ret != PDPASS) {
        s_started = false;
        return false;
    }
    return true;
}

void mdns_dispatch_reset(void)
{
    s_started = false;
}
