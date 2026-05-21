/*
 * zeroize.c -- volatile memory wipe implementation
 */

#include "zeroize.h"

void zeroize(volatile void *mem, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)mem;
    while (len--) *p++ = 0;
}
