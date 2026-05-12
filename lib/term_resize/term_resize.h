/*
 * term_resize.h — pure formatter for the xterm "set window size" CSI sequence
 *
 * Extracted from ssh_server.c's term_resize_cb so the formatting (i.e. the
 * sole non-trivial piece of logic in that callback) can be unit-tested on the
 * native host without ESP-IDF / wolfSSH present.
 *
 * No I/O, no platform dependencies — just snprintf into a caller-supplied
 * buffer.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Format an xterm "set window size" CSI sequence into `out`.
 *
 *   \033[8;<rows>;<cols>t
 *
 * Returns the number of bytes written to `out` (not counting any
 * implicit NUL), or 0 if:
 *   - cols == 0 or rows == 0 (caller should ignore the resize event)
 *   - out is NULL
 *   - out_sz is too small to hold the full sequence + NUL
 *
 * The function always NUL-terminates `out` when it returns > 0.
 *
 * For typical values (cols=80, rows=24) the formatted sequence is 10 bytes
 * ("\033[8;24;80t"), so out_sz of 32 is comfortable.
 */
int term_resize_format(uint32_t cols, uint32_t rows, char *out, size_t out_sz);

#ifdef __cplusplus
}
#endif
