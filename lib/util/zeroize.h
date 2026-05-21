/*
 * zeroize.h -- volatile memory wipe to prevent dead-store elimination
 *
 * Used to clear key material from buffers before they go out of scope.
 * The volatile pointer write sequence cannot be optimised away by the
 * compiler even when the buffer is immediately freed or goes out of scope.
 */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * zeroize -- overwrite mem with zero bytes.
 *
 * Equivalent to memset(mem, 0, len) but guaranteed not to be elided by
 * the compiler as a dead store.
 */
void zeroize(volatile void *mem, size_t len);

#ifdef __cplusplus
}
#endif
