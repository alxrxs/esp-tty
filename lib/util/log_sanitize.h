/*
 * log_sanitize.h -- escape attacker-controlled bytes before logging
 *
 * Untrusted input (SSH usernames, EAP identities, OTA paths, DNS names,
 * anything parsed off the wire / out of NVS) may contain control bytes,
 * newlines, or ANSI escape sequences.  Logging such input verbatim --
 * especially when forwarded over a cleartext UDP log channel -- allows
 * an attacker to forge log lines or confuse terminal-based log viewers.
 *
 * log_sanitize() copies up to `in_len` bytes from `in` into `out`,
 * replacing every byte outside the printable-ASCII safe set
 * ([0x20..0x7e] minus the quote characters and backslash) with the
 * literal three-character sequence "\xHH" (4 chars including the
 * backslash).  The output is always NUL-terminated, even when the
 * caller's buffer is too small (in which case the output is truncated).
 *
 * Designed for use in `ESP_LOGW(... "%s", sanitized)` paths.  Do NOT use
 * for cryptographic or parsing purposes -- only for human-readable log
 * lines.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * log_sanitize -- write a printable, NUL-terminated copy of `in` into `out`.
 *
 * Bytes in the safe range (0x20..0x7e, excluding 0x22 '"', 0x27 '\'',
 * and 0x5c '\\') are copied verbatim.  Any other byte is rendered as
 * the four characters "\xHH" (lowercase hex).
 *
 * If the buffer would overflow, the output is truncated.  The result
 * is always NUL-terminated as long as out_cap >= 1.  If out_cap == 0
 * the function does nothing.
 *
 * Returns the number of bytes (excluding the trailing NUL) that were
 * written.  Callers can use this as a sanity-check but are not
 * required to.
 */
size_t log_sanitize(char *out, size_t out_cap,
                    const void *in, size_t in_len);

#ifdef __cplusplus
}
#endif
