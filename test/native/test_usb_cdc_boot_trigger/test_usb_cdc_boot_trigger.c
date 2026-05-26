/*
 * test_usb_cdc_boot_trigger.c -- unit tests for the CDC RX magic-sequence
 * matcher used as the out-of-band recovery path on the ESP32-S3-Zero.
 */

#include <unity.h>
#include <string.h>
#include <stdint.h>

#include "usb_cdc_boot_trigger.h"

static usb_cdc_boot_trigger_t t;

void setUp(void)    { usb_cdc_boot_trigger_init(&t); }
void tearDown(void) {}

/* Feed a NUL-terminated C string byte-by-byte and return true if any byte
 * triggered a match. */
static bool feed_str(usb_cdc_boot_trigger_t *s, const char *str)
{
    bool triggered = false;
    for (const uint8_t *p = (const uint8_t *)str; *p; p++) {
        if (usb_cdc_boot_trigger_feed(s, *p)) triggered = true;
    }
    return triggered;
}

/* Feed `n` bytes and return how many trigger fires happened. */
static int feed_bytes_counted(usb_cdc_boot_trigger_t *s,
                              const uint8_t *bytes, size_t n)
{
    int fires = 0;
    for (size_t i = 0; i < n; i++) {
        if (usb_cdc_boot_trigger_feed(s, bytes[i])) fires++;
    }
    return fires;
}

void test_empty_init_no_match(void)
{
    TEST_ASSERT_EQUAL_size_t(0, t.matched);
}

void test_null_state_safe(void)
{
    /* Must not crash and must not claim a match. */
    TEST_ASSERT_FALSE(usb_cdc_boot_trigger_feed(NULL, 'x'));
    usb_cdc_boot_trigger_init(NULL);  /* must not crash */
}

void test_magic_full_sequence_matches(void)
{
    const uint8_t *m = usb_cdc_boot_trigger_magic();
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    int fires = feed_bytes_counted(&t, m, mlen);
    TEST_ASSERT_EQUAL_INT(1, fires);
}

void test_no_match_on_normal_console_traffic(void)
{
    /* A chunk of realistic Linux boot-log noise must not trigger. */
    const char *noise =
        "[    0.000000] Linux version 6.5.7-arch1-1 (linux@archlinux)\n"
        "[    0.001234] Command line: BOOT_IMAGE=/vmlinuz-linux root=UUID=...\n"
        "[    0.123456] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point'\n"
        "login: root\nPassword: \n# uname -a\nLinux esp-tty 6.5\n";
    TEST_ASSERT_FALSE(feed_str(&t, noise));
}

void test_partial_then_garbage_then_full_match(void)
{
    /* Leading partial prefix of magic, then garbage that doesn't restart
     * the match, then a clean full magic. */
    feed_str(&t, "\nESPTTY_REB");                /* partial */
    feed_str(&t, "XYZ-not-the-magic-blah\r");   /* mismatch -- reset */
    const uint8_t *m = usb_cdc_boot_trigger_magic();
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    int fires = feed_bytes_counted(&t, m, mlen);
    TEST_ASSERT_EQUAL_INT(1, fires);
}

void test_back_to_back_matches_fire_twice(void)
{
    const uint8_t *m = usb_cdc_boot_trigger_magic();
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    int fires = 0;
    fires += feed_bytes_counted(&t, m, mlen);
    fires += feed_bytes_counted(&t, m, mlen);
    TEST_ASSERT_EQUAL_INT(2, fires);
}

void test_mismatch_recovery_to_start_byte(void)
{
    /* The magic starts with '\n'.  After a mismatch on byte k, if the
     * mismatching byte is '\n' we must already be at match-position 1
     * (not 0) so the next byte can continue the match.  Otherwise an
     * accidental "<garbage>\n<magic>" stream would miss. */
    feed_str(&t, "\nESPTTY_X");                   /* mismatch on 'X' */
    TEST_ASSERT_EQUAL_size_t(0, t.matched);       /* X is not '\n' -- reset to 0 */
    feed_str(&t, "\n");                           /* now '\n' arrives */
    TEST_ASSERT_EQUAL_size_t(1, t.matched);       /* start byte aligned */
}

void test_byte_split_across_chunks_matches(void)
{
    /* Real CDC RX FIFO gives 64-byte chunks; the magic is longer than
     * one byte, so the matcher MUST survive chunk boundaries.
     * Feed the magic one byte at a time -- this is exactly the
     * worst-case fragmentation. */
    const uint8_t *m = usb_cdc_boot_trigger_magic();
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    bool triggered = false;
    for (size_t i = 0; i < mlen; i++) {
        if (usb_cdc_boot_trigger_feed(&t, m[i])) triggered = true;
    }
    TEST_ASSERT_TRUE(triggered);
}

void test_magic_is_nl_bracketed_body_has_no_nl(void)
{
    /* This invariant is what makes the simple mismatch-recovery
     * (reset to 1 only if byte == magic[0]) correct.  If the body
     * contains '\n', a more elaborate KMP table would be required. */
    const uint8_t *m = usb_cdc_boot_trigger_magic();
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    TEST_ASSERT_EQUAL_UINT8('\n', m[0]);
    TEST_ASSERT_EQUAL_UINT8('\n', m[mlen - 1]);
    for (size_t i = 1; i < mlen - 1; i++) {
        TEST_ASSERT_NOT_EQUAL_INT('\n', m[i]);
    }
}

void test_magic_reasonable_length(void)
{
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    /* Long enough to be unmistakable, short enough to fit a single
     * recovery-script write_all() comfortably. */
    TEST_ASSERT_GREATER_THAN_size_t(32, mlen);
    TEST_ASSERT_LESS_THAN_size_t(128, mlen);
}

void test_match_resets_state_so_next_byte_starts_fresh(void)
{
    const uint8_t *m = usb_cdc_boot_trigger_magic();
    size_t mlen = usb_cdc_boot_trigger_magic_len();
    feed_bytes_counted(&t, m, mlen);              /* triggers once */
    TEST_ASSERT_EQUAL_size_t(0, t.matched);       /* state reset */

    /* Now feed a byte that is NOT the magic start -- still no match. */
    TEST_ASSERT_FALSE(usb_cdc_boot_trigger_feed(&t, 'q'));
    TEST_ASSERT_EQUAL_size_t(0, t.matched);
}

/* ------------------------------------------------------------------ */
/* NEW: adversarial partial-prefix mismatch sequences                  */

/* Feed magic[0..k-1] then a byte that differs from magic[k] at each
 * position k.  None should trigger; a subsequent full magic must still
 * match cleanly.                                                       */
void test_mismatch_at_every_position_no_spurious_fire(void)
{
    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();

    for (size_t k = 1; k < mlen; k++) {
        usb_cdc_boot_trigger_t s;
        usb_cdc_boot_trigger_init(&s);

        /* Feed matching prefix up to position k-1 */
        for (size_t j = 0; j < k; j++) {
            bool fire = usb_cdc_boot_trigger_feed(&s, m[j]);
            TEST_ASSERT_FALSE(fire);
        }

        /* Feed a definitely-wrong byte (complement of m[k], avoiding '\n'
         * which is the restart-byte and would set matched=1).           */
        uint8_t bad = (uint8_t)(~m[k]);
        if (bad == '\n') bad = '?';
        bool fire = usb_cdc_boot_trigger_feed(&s, bad);
        TEST_ASSERT_FALSE(fire);

        /* Now feed a full correct magic: must fire exactly once */
        int fires = 0;
        for (size_t j = 0; j < mlen; j++)
            if (usb_cdc_boot_trigger_feed(&s, m[j])) fires++;
        TEST_ASSERT_EQUAL_INT(1, fires);
    }
}

/* An almost-correct sequence that diverges only on the LAST byte
 * (magic[mlen-1]) must not fire.                                       */
void test_diverge_on_last_byte_no_fire(void)
{
    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();

    /* Feed all but the last byte correctly */
    for (size_t i = 0; i < mlen - 1; i++) {
        TEST_ASSERT_FALSE(usb_cdc_boot_trigger_feed(&t, m[i]));
    }
    /* Feed a wrong final byte (magic ends with '\n'; send a non-'\n') */
    TEST_ASSERT_FALSE(usb_cdc_boot_trigger_feed(&t, 'X'));
}

/* Interleaved noise between correct magic bytes: no fire.             */
void test_noise_interleaved_in_magic_no_fire(void)
{
    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();
    bool fire = false;

    /* Alternate: correct byte, noise byte -- should never fire because
     * the noise breaks the match at each second byte.                 */
    for (size_t i = 0; i < mlen; i++) {
        if (usb_cdc_boot_trigger_feed(&t, m[i])) fire = true;
        if (i < mlen - 1)
            if (usb_cdc_boot_trigger_feed(&t, 'Q')) fire = true;
    }
    TEST_ASSERT_FALSE(fire);
}

/* Five consecutive full magic sequences: must fire exactly five times. */
void test_five_consecutive_matches(void)
{
    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();
    int fires = 0;

    for (int rep = 0; rep < 5; rep++)
        for (size_t i = 0; i < mlen; i++)
            if (usb_cdc_boot_trigger_feed(&t, m[i])) fires++;

    TEST_ASSERT_EQUAL_INT(5, fires);
}

/* Magic with '\n' start byte: feed the magic as if it were preceded by
 * an unrelated '\n' in the stream (the '\n' is magic[0], so the
 * preceding '\n' starts a fresh match attempt).                        */
void test_magic_immediately_after_stray_newline(void)
{
    /* Feed a stray '\n' -- which IS magic[0], so matched becomes 1 */
    bool fire = usb_cdc_boot_trigger_feed(&t, '\n');
    TEST_ASSERT_FALSE(fire);

    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();

    /* The stray '\n' already matched magic[0].  Now feed magic[1..end].
     * This must complete the sequence and fire exactly once.           */
    int fires = 0;
    for (size_t i = 1; i < mlen; i++)
        if (usb_cdc_boot_trigger_feed(&t, m[i])) fires++;

    TEST_ASSERT_EQUAL_INT(1, fires);
}

/* Partial prefix match where the mismatching byte happens to be '\n'
 * (start byte).  The spec says matched resets to 1 in that case.
 * Verify the matcher correctly transitions, then completes on a
 * subsequently fed full magic-sans-first-byte.                        */
void test_mismatch_byte_is_newline_restarts_at_1(void)
{
    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();

    /* Feed magic[0..3] (partial) */
    for (size_t i = 0; i < 4; i++)
        TEST_ASSERT_FALSE(usb_cdc_boot_trigger_feed(&t, m[i]));

    /* Feed '\n' as the mismatching byte at position 4.
     * '\n' == magic[0], so matched should become 1.              */
    TEST_ASSERT_FALSE(usb_cdc_boot_trigger_feed(&t, '\n'));
    TEST_ASSERT_EQUAL_size_t(1, t.matched);

    /* Now feed magic[1..end] to complete the match */
    int fires = 0;
    for (size_t i = 1; i < mlen; i++)
        if (usb_cdc_boot_trigger_feed(&t, m[i])) fires++;
    TEST_ASSERT_EQUAL_INT(1, fires);
}

/* After a match the state resets to 0; the very next byte that is not
 * magic[0] must leave matched at 0 (no phantom partial state).       */
void test_after_match_non_start_byte_stays_zero(void)
{
    const uint8_t *m    = usb_cdc_boot_trigger_magic();
    size_t         mlen = usb_cdc_boot_trigger_magic_len();

    /* Complete one match */
    for (size_t i = 0; i < mlen; i++)
        usb_cdc_boot_trigger_feed(&t, m[i]);

    TEST_ASSERT_EQUAL_size_t(0, t.matched);

    /* Feed a non-start byte; matched must remain 0 */
    usb_cdc_boot_trigger_feed(&t, 'Z');
    TEST_ASSERT_EQUAL_size_t(0, t.matched);
}

/* Feed every possible single-byte value; none should trigger a match
 * on its own (magic is longer than 1 byte).                          */
void test_single_byte_never_triggers_match(void)
{
    for (int b = 0; b < 256; b++) {
        usb_cdc_boot_trigger_t s;
        usb_cdc_boot_trigger_init(&s);
        bool fire = usb_cdc_boot_trigger_feed(&s, (uint8_t)b);
        TEST_ASSERT_FALSE(fire);
    }
}

/* ------------------------------------------------------------------ */
int app_main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_empty_init_no_match);
    RUN_TEST(test_null_state_safe);
    RUN_TEST(test_magic_full_sequence_matches);
    RUN_TEST(test_no_match_on_normal_console_traffic);
    RUN_TEST(test_partial_then_garbage_then_full_match);
    RUN_TEST(test_back_to_back_matches_fire_twice);
    RUN_TEST(test_mismatch_recovery_to_start_byte);
    RUN_TEST(test_byte_split_across_chunks_matches);
    RUN_TEST(test_magic_is_nl_bracketed_body_has_no_nl);
    RUN_TEST(test_magic_reasonable_length);
    RUN_TEST(test_match_resets_state_so_next_byte_starts_fresh);
    /* NEW adversarial tests */
    RUN_TEST(test_mismatch_at_every_position_no_spurious_fire);
    RUN_TEST(test_diverge_on_last_byte_no_fire);
    RUN_TEST(test_noise_interleaved_in_magic_no_fire);
    RUN_TEST(test_five_consecutive_matches);
    RUN_TEST(test_magic_immediately_after_stray_newline);
    RUN_TEST(test_mismatch_byte_is_newline_restarts_at_1);
    RUN_TEST(test_after_match_non_start_byte_stays_zero);
    RUN_TEST(test_single_byte_never_triggers_match);
    return UNITY_END();
}

int main(void) { return app_main(); }
