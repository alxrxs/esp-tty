/*
 * term_resize.c -- pure formatter for the xterm "set window size" CSI sequence
 *
 * See term_resize.h for the contract.  No ESP-IDF / wolfSSH dependencies --
 * builds on the native test host as-is.
 */

#include "term_resize.h"

#include <stdio.h>

int term_resize_format(uint32_t cols, uint32_t rows, char *out, size_t out_sz)
{
    /* Defensive zero-returns: each of these is a "do not produce a sequence"
     * signal.  The caller (ssh_server.c's term_resize_cb) also early-returns
     * on the zero-dimension cases, but duplicating the check here means the
     * helper is safe to call standalone. */
    if (cols == 0 || rows == 0) return 0;
    if (out == NULL)            return 0;
    if (out_sz == 0)            return 0;

    /* snprintf returns the number of bytes that *would* have been written
     * (excluding the NUL), regardless of truncation.  If that count is >=
     * out_sz, the output was truncated -- treat as "buffer too small" and
     * return 0 so the caller doesn't emit a half-formed CSI sequence. */
    int n = snprintf(out, out_sz, "\033[8;%u;%ut",
                     (unsigned)rows, (unsigned)cols);

    if (n <= 0)                 return 0;  /* encoding error (should not happen) */
    if ((size_t)n >= out_sz)    return 0;  /* truncated -- no room for NUL */

    return n;
}
