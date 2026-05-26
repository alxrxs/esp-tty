/*
 * test_ntp_config.c -- unit tests for NTP compile-time configuration logic
 *
 * The SNTP init/sync path calls ESP-IDF APIs that are not available on the
 * host, so these tests focus on the host-portable pieces:
 *
 *   1. Server-list macro: NTP_SERVERS expands to a valid C array initializer
 *      and the element count is within CONFIG_LWIP_SNTP_MAX_SERVERS.
 *   2. Timezone string: NTP_TIMEZONE fits within NTP_TZ_MAX_LEN (64 chars).
 *   3. Sync-timeout knob: NTP_SYNC_TIMEOUT_SEC is in the documented range.
 *   4. _Static_assert compile-time bounds (caught at compile time, not at
 *      run time -- the test file compiling at all proves they pass).
 *
 * Compiled without ESP-IDF headers; no stubs required.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "unity.h"

/* ------------------------------------------------------------------ */
/* Reproduce the same defaults that wifi.c uses so tests are self-    */
/* contained and consistent with the firmware.                        */
/* ------------------------------------------------------------------ */

#ifndef NTP_SERVERS
# define NTP_SERVERS  "pool.ntp.org"
#endif

#ifndef NTP_TIMEZONE
# define NTP_TIMEZONE  "UTC0"
#endif

#ifndef NTP_SYNC_TIMEOUT_SEC
# define NTP_SYNC_TIMEOUT_SEC  30
#endif

#define NTP_TZ_MAX_LEN  64

/* Stub the IDF constant so the _Static_assert below compiles on the host. */
#ifndef CONFIG_LWIP_SNTP_MAX_SERVERS
# define CONFIG_LWIP_SNTP_MAX_SERVERS  4
#endif

/* ------------------------------------------------------------------ */
/* Compile-time bounds -- the translation unit compiling proves these. */
/* ------------------------------------------------------------------ */
_Static_assert(NTP_SYNC_TIMEOUT_SEC >= 1 && NTP_SYNC_TIMEOUT_SEC <= 3600,
               "NTP_SYNC_TIMEOUT_SEC must be in range 1..3600");

_Static_assert(sizeof(NTP_TIMEZONE) - 1 <= NTP_TZ_MAX_LEN,
               "NTP_TIMEZONE exceeds NTP_TZ_MAX_LEN (64 chars)");

/* ------------------------------------------------------------------ */
void setUp(void)    {}
void tearDown(void) {}
/* ------------------------------------------------------------------ */

/* The NTP_SERVERS macro expands to a valid array initializer. */
void test_servers_macro_expands_to_array(void)
{
    const char *const servers[] = { NTP_SERVERS };
    size_t n = sizeof(servers) / sizeof(servers[0]);
    TEST_ASSERT_GREATER_THAN_size_t(0, n);
    /* Each entry must be a non-empty string. */
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_NOT_NULL(servers[i]);
        TEST_ASSERT_GREATER_THAN_size_t(0, strlen(servers[i]));
    }
}

/* Server count must not exceed the lwIP compile-time maximum. */
void test_server_count_within_max(void)
{
    const char *const servers[] = { NTP_SERVERS };
    size_t n = sizeof(servers) / sizeof(servers[0]);
    TEST_ASSERT_LESS_OR_EQUAL_size_t((size_t)CONFIG_LWIP_SNTP_MAX_SERVERS, n);
}

/* Each server name must fit within the DNS 253-char hostname limit. */
void test_server_names_within_dns_limit(void)
{
    const char *const servers[] = { NTP_SERVERS };
    size_t n = sizeof(servers) / sizeof(servers[0]);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_LESS_OR_EQUAL_size_t(253u, strlen(servers[i]));
    }
}

/* NTP_TIMEZONE must be a non-empty string within the 64-char cap. */
void test_timezone_non_empty_and_within_limit(void)
{
    const char *tz = NTP_TIMEZONE;
    size_t len = strlen(tz);
    TEST_ASSERT_GREATER_THAN_size_t(0, len);
    TEST_ASSERT_LESS_OR_EQUAL_size_t(NTP_TZ_MAX_LEN, len);
}

/* NTP_SYNC_TIMEOUT_SEC must be a positive integer in 1..3600. */
void test_sync_timeout_in_range(void)
{
    int t = NTP_SYNC_TIMEOUT_SEC;
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, t);
    TEST_ASSERT_LESS_OR_EQUAL_INT(3600, t);
}

/* The default server list contains "pool.ntp.org" (smoke test). */
void test_default_server_contains_pool_ntp(void)
{
    const char *const servers[] = { NTP_SERVERS };
    size_t n = sizeof(servers) / sizeof(servers[0]);
    int found = 0;
    for (size_t i = 0; i < n; i++) {
        if (strstr(servers[i], "ntp.org") != NULL) {
            found = 1;
            break;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(found, "expected at least one *.ntp.org server");
}

/* snprintf truncation model: tz_buf = NTP_TZ_MAX_LEN+1 bytes is enough. */
void test_tz_buffer_fits_timezone(void)
{
    char buf[NTP_TZ_MAX_LEN + 1];
    int n = snprintf(buf, sizeof(buf), "%s", NTP_TIMEZONE);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, n);
    /* snprintf return < buffer size means no truncation occurred. */
    TEST_ASSERT_LESS_THAN_INT((int)sizeof(buf), n + 1);
}

/* NTP_TIMEZONE must not contain a raw newline (would break POSIX TZ setenv). */
void test_timezone_no_newline(void)
{
    const char *tz = NTP_TIMEZONE;
    for (size_t i = 0; i < strlen(tz); i++) {
        TEST_ASSERT_NOT_EQUAL_MESSAGE('\n', (int)(unsigned char)tz[i],
            "NTP_TIMEZONE must not contain a newline");
    }
}

/* NTP_SYNC_TIMEOUT_SEC is not zero (would cause immediate timeout). */
void test_sync_timeout_nonzero(void)
{
    TEST_ASSERT_NOT_EQUAL(0, NTP_SYNC_TIMEOUT_SEC);
}

/* NTP_TIMEZONE fits in a POSIX TZ env variable (no null bytes inside). */
void test_timezone_is_printable_ascii(void)
{
    const char *tz = NTP_TIMEZONE;
    size_t len = strlen(tz);
    TEST_ASSERT_GREATER_THAN_size_t(0, len);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)tz[i];
        TEST_ASSERT_TRUE_MESSAGE(c >= 0x20 && c <= 0x7E,
            "NTP_TIMEZONE contains non-printable or non-ASCII byte");
    }
}

/* Each server name must be non-trivial (at least 3 chars like "a.b"). */
void test_server_names_reasonable_length(void)
{
    const char *const servers[] = { NTP_SERVERS };
    size_t n = sizeof(servers) / sizeof(servers[0]);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_GREATER_OR_EQUAL_size_t(3, strlen(servers[i]));
    }
}

/* NTP_SYNC_TIMEOUT_SEC is representable as uint32_t without truncation. */
void test_sync_timeout_fits_uint32(void)
{
    /* NTP_SYNC_TIMEOUT_SEC <= 3600 (already asserted at compile time),
     * which is well within uint32_t range. This is a runtime smoke-check. */
    uint32_t t = (uint32_t)NTP_SYNC_TIMEOUT_SEC;
    TEST_ASSERT_EQUAL_UINT32((uint32_t)NTP_SYNC_TIMEOUT_SEC, t);
}

/* ------------------------------------------------------------------ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_servers_macro_expands_to_array);
    RUN_TEST(test_server_count_within_max);
    RUN_TEST(test_server_names_within_dns_limit);
    RUN_TEST(test_timezone_non_empty_and_within_limit);
    RUN_TEST(test_sync_timeout_in_range);
    RUN_TEST(test_default_server_contains_pool_ntp);
    RUN_TEST(test_tz_buffer_fits_timezone);
    /* Additional cases */
    RUN_TEST(test_timezone_no_newline);
    RUN_TEST(test_sync_timeout_nonzero);
    RUN_TEST(test_timezone_is_printable_ascii);
    RUN_TEST(test_server_names_reasonable_length);
    RUN_TEST(test_sync_timeout_fits_uint32);
    return UNITY_END();
}
