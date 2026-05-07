/*
 * bridge.c — pure byte pump, no platform dependencies
 */

#include "bridge.h"

#define BRIDGE_BUF_SIZE 4096

void bridge_pump(bridge_read_fn  r, void *r_ctx,
                 bridge_write_fn w, void *w_ctx,
                 volatile bool  *stop)
{
    uint8_t buf[BRIDGE_BUF_SIZE];

    while (!*stop) {
        int n = r(r_ctx, buf, sizeof(buf));
        if (n <= 0) break;  /* EOF or error on read side */

        int written = w(w_ctx, buf, (size_t)n);
        if (written <= 0) break;  /* error on write side */
    }
}
