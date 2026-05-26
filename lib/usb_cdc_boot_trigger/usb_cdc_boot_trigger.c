/*
 * usb_cdc_boot_trigger.c -- pure C byte-matcher for the USB CDC RX
 * boot-to-bootloader magic sequence.  No platform deps.
 */

#include "usb_cdc_boot_trigger.h"

#include <string.h>

/* The magic sequence.  Bracketed by '\n' so the body has no '\n'; this
 * keeps the mismatch-recovery branch trivial (see feed()).
 *
 * If you change this string, update test/native/test_usb_cdc_boot_trigger/
 * accordingly -- but think twice: every deployed device that doesn't
 * have the new build will not recognise the new magic, and the OTA
 * channel may already be down (which is the whole point of this
 * recovery path). */
static const uint8_t k_magic[] =
    "\nESPTTY_REBOOT_TO_BOOTLOADER_xK9w7Pq3J8dHvR_NOW\n";

/* sizeof includes the trailing NUL written by the C string literal; we
 * exclude it from the match length. */
#define K_MAGIC_LEN (sizeof(k_magic) - 1)

const uint8_t *usb_cdc_boot_trigger_magic(void)     { return k_magic; }
size_t         usb_cdc_boot_trigger_magic_len(void) { return K_MAGIC_LEN; }

void usb_cdc_boot_trigger_init(usb_cdc_boot_trigger_t *s)
{
    if (!s) return;
    s->matched = 0;
}

bool usb_cdc_boot_trigger_feed(usb_cdc_boot_trigger_t *s, uint8_t b)
{
    if (!s) return false;

    if (b == k_magic[s->matched]) {
        s->matched++;
        if (s->matched == K_MAGIC_LEN) {
            s->matched = 0;
            return true;
        }
        return false;
    }

    /* Mismatch.  Because the body of k_magic contains no occurrence of
     * k_magic[0], the only way `b` could be the start of a fresh match
     * is if `b == k_magic[0]`. */
    s->matched = (b == k_magic[0]) ? 1u : 0u;
    return false;
}
