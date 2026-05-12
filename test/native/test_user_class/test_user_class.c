/*
 * test_user_class.c — unit tests for pubkey_classify_user()
 *
 * "tty" → PUBKEY_USER_TTY, "ota" → PUBKEY_USER_OTA, everything else →
 * PUBKEY_USER_REJECTED (including NULL, empty, case variants, and typos).
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#include "unity.h"
#include "pubkey_auth.h"

void setUp(void)    {}
void tearDown(void) {}

/* ── "ota" cases ─────────────────────────────────────────────────────────── */

void test_classify_ota_exact(void)
{
    pubkey_user_class_t c = pubkey_classify_user("ota", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_OTA, c);
}

void test_classify_ota_with_nul_in_middle(void)
{
    /* We pass length=3 so only "ota" is considered; the trailing NUL is ignored */
    const char user[] = "ota\0extra";
    pubkey_user_class_t c = pubkey_classify_user(user, 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_OTA, c);
}

void test_classify_ota_with_claimed_length_4_is_rejected(void)
{
    /* "ota\n" (length 4) — extra byte makes it not equal to "ota" */
    pubkey_user_class_t c = pubkey_classify_user("ota\n", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

/* ── "tty" cases ─────────────────────────────────────────────────────────── */

void test_classify_tty_exact(void)
{
    pubkey_user_class_t c = pubkey_classify_user("tty", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_TTY, c);
}

void test_classify_tty_with_nul_in_middle(void)
{
    const char user[] = "tty\0extra";
    pubkey_user_class_t c = pubkey_classify_user(user, 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_TTY, c);
}

/* ── Rejected cases ──────────────────────────────────────────────────────── */

void test_classify_uppercase_ota_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("OTA", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_uppercase_tty_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("TTY", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_longer_string_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("ota_user", 8);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_shorter_string_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("ot", 2);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_empty_string_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("", 0);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_null_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user(NULL, 0);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_root_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("root", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_andrei_is_rejected(void)
{
    pubkey_user_class_t c = pubkey_classify_user("andrei", 6);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

/* ── Additional edge-case rejections ─────────────────────────────────────── */

void test_classify_tty_with_trailing_cr(void)
{
    pubkey_user_class_t c = pubkey_classify_user("tty\r", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_tty_with_trailing_lf(void)
{
    pubkey_user_class_t c = pubkey_classify_user("tty\n", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_tty_with_trailing_space(void)
{
    pubkey_user_class_t c = pubkey_classify_user("tty ", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_tty_with_leading_space(void)
{
    pubkey_user_class_t c = pubkey_classify_user(" tty", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_mixed_case_tTy(void)
{
    /* Case-sensitive at every position — uppercase middle byte rejects */
    pubkey_user_class_t c = pubkey_classify_user("tTy", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_oTa(void)
{
    pubkey_user_class_t c = pubkey_classify_user("oTa", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_very_long_username(void)
{
    /* Must not crash on absurdly long input — just reject cleanly */
    char buf[256];
    memset(buf, 'x', 256);
    pubkey_user_class_t c = pubkey_classify_user(buf, 256);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_unicode_bytes(void)
{
    /* UTF-8 'é' (0xC3 0xA9) followed by 'y' — three bytes, not "tty"/"ota" */
    const unsigned char u[3] = {0xC3, 0xA9, 'y'};
    pubkey_user_class_t c = pubkey_classify_user((const char *)u, 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_username_with_embedded_nul(void)
{
    /* Embedded NUL in the middle; claimed length 5 is not 3 → rejected */
    const char user[] = "tt\0y\0";
    pubkey_user_class_t c = pubkey_classify_user(user, 5);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

void test_classify_partial_match_with_extra_byte(void)
{
    pubkey_user_class_t c = pubkey_classify_user("ttyx", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_REJECTED, c);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_classify_ota_exact);
    RUN_TEST(test_classify_ota_with_nul_in_middle);
    RUN_TEST(test_classify_ota_with_claimed_length_4_is_rejected);
    RUN_TEST(test_classify_tty_exact);
    RUN_TEST(test_classify_tty_with_nul_in_middle);
    RUN_TEST(test_classify_uppercase_ota_is_rejected);
    RUN_TEST(test_classify_uppercase_tty_is_rejected);
    RUN_TEST(test_classify_longer_string_is_rejected);
    RUN_TEST(test_classify_shorter_string_is_rejected);
    RUN_TEST(test_classify_empty_string_is_rejected);
    RUN_TEST(test_classify_null_is_rejected);
    RUN_TEST(test_classify_root_is_rejected);
    RUN_TEST(test_classify_andrei_is_rejected);
    RUN_TEST(test_classify_tty_with_trailing_cr);
    RUN_TEST(test_classify_tty_with_trailing_lf);
    RUN_TEST(test_classify_tty_with_trailing_space);
    RUN_TEST(test_classify_tty_with_leading_space);
    RUN_TEST(test_classify_mixed_case_tTy);
    RUN_TEST(test_classify_oTa);
    RUN_TEST(test_classify_very_long_username);
    RUN_TEST(test_classify_unicode_bytes);
    RUN_TEST(test_classify_username_with_embedded_nul);
    RUN_TEST(test_classify_partial_match_with_extra_byte);
    return UNITY_END();
}
