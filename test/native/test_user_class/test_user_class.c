/*
 * test_user_class.c — unit tests for pubkey_classify_user()
 *
 * Tests the pure username-to-user-class mapping that routes SSH auth to
 * either the normal authorized key hash (PUBKEY_USER_DEFAULT) or the OTA
 * authorized key hash (PUBKEY_USER_OTA).
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#include "unity.h"
#include "pubkey_auth.h"

void setUp(void)    {}
void tearDown(void) {}

/* ── Core routing cases ──────────────────────────────────────────────────── */

void test_classify_ota_exact(void)
{
    /* "ota" (length 3) → OTA session */
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

void test_classify_uppercase_ota_is_default(void)
{
    /* Case-sensitive: "OTA" is NOT the OTA user */
    pubkey_user_class_t c = pubkey_classify_user("OTA", 3);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

void test_classify_longer_string_is_default(void)
{
    /* "ota_user" (length 8) — longer, so not "ota" */
    pubkey_user_class_t c = pubkey_classify_user("ota_user", 8);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

void test_classify_shorter_string_is_default(void)
{
    /* "ot" (length 2) — shorter, so not "ota" */
    pubkey_user_class_t c = pubkey_classify_user("ot", 2);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

void test_classify_empty_string_is_default(void)
{
    /* Empty string → default */
    pubkey_user_class_t c = pubkey_classify_user("", 0);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

void test_classify_null_is_default(void)
{
    /* NULL pointer → default without crash */
    pubkey_user_class_t c = pubkey_classify_user(NULL, 0);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

/* ── Additional edge cases ───────────────────────────────────────────────── */

void test_classify_normal_user_is_default(void)
{
    pubkey_user_class_t c = pubkey_classify_user("root", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

void test_classify_ota_with_claimed_length_4_is_default(void)
{
    /* "ota\n" (length 4) — the extra byte makes it not equal to "ota" */
    pubkey_user_class_t c = pubkey_classify_user("ota\n", 4);
    TEST_ASSERT_EQUAL_INT(PUBKEY_USER_DEFAULT, c);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_classify_ota_exact);
    RUN_TEST(test_classify_ota_with_nul_in_middle);
    RUN_TEST(test_classify_uppercase_ota_is_default);
    RUN_TEST(test_classify_longer_string_is_default);
    RUN_TEST(test_classify_shorter_string_is_default);
    RUN_TEST(test_classify_empty_string_is_default);
    RUN_TEST(test_classify_null_is_default);
    RUN_TEST(test_classify_normal_user_is_default);
    RUN_TEST(test_classify_ota_with_claimed_length_4_is_default);
    return UNITY_END();
}
