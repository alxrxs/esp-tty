/*
 * log_sanitize.c -- see log_sanitize.h
 */

#include "log_sanitize.h"

static char hexc(unsigned v)
{
    v &= 0xf;
    return (char)(v < 10 ? ('0' + v) : ('a' + v - 10));
}

static int is_safe(unsigned char b)
{
    /* Printable ASCII excluding the three characters that commonly
     * confuse log parsers / shells: '"', '\'' and '\\'. */
    if (b < 0x20 || b > 0x7e) return 0;
    if (b == 0x22 || b == 0x27 || b == 0x5c) return 0;
    return 1;
}

size_t log_sanitize(char *out, size_t out_cap,
                    const void *in, size_t in_len)
{
    if (!out || out_cap == 0) return 0;
    if (!in) in_len = 0;

    const unsigned char *src = (const unsigned char *)in;
    size_t w = 0;

    for (size_t i = 0; i < in_len; i++) {
        unsigned char b = src[i];
        if (is_safe(b)) {
            if (w + 1 >= out_cap) break; /* leave room for NUL */
            out[w++] = (char)b;
        } else {
            /* "\xHH" -- 4 bytes */
            if (w + 4 >= out_cap) break;
            out[w++] = '\\';
            out[w++] = 'x';
            out[w++] = hexc(b >> 4);
            out[w++] = hexc(b);
        }
    }
    out[w] = '\0';
    return w;
}
