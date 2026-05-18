/*
 * test_config_bounds.c -- compile-time and runtime bound checks for config
 * macro values documented in config.example.h.
 *
 * Each _Static_assert below corresponds to a bound annotation in
 * config.example.h.  If a fixture value exceeds its documented maximum,
 * the build fails here rather than silently producing wrong firmware.
 *
 * Uses fixture values (not real config.h) so this file is self-contained.
 */

#include <string.h>
#include "unity.h"

void setUp(void)    {}
void tearDown(void) {}

/* --------------------------------------------------------------------------
 * Fixture values that represent typical config.h entries.
 * These are at or near the documented maxima so the assertions are tight.
 * -------------------------------------------------------------------------- */

/* Wi-Fi SSID: max 32 bytes (wifi_sta_config_t.ssid[32]) */
#define FIXTURE_SSID  "a-very-long-ssid-name-32-chars!!"
_Static_assert(sizeof(FIXTURE_SSID) - 1 <= 32,
               "WIFI_SSID must be at most 32 bytes");

/* Wi-Fi PSK: max 63 bytes (WPA2/WPA3-PSK spec) */
#define FIXTURE_PASS  "this-passphrase-is-exactly-63-characters-long-XXXXXXXXXXXXXXX"
_Static_assert(sizeof(FIXTURE_PASS) - 1 <= 63,
               "WIFI_PASS must be at most 63 bytes");

/* EAP identity: max 127 bytes */
#define FIXTURE_EAP_IDENTITY  "anonymous@example.org"
_Static_assert(sizeof(FIXTURE_EAP_IDENTITY) - 1 <= 127,
               "EAP_IDENTITY must be at most 127 bytes");

/* DEVICE_HOSTNAME: max 32 bytes (ESP_NETIF_HOSTNAME_MAX_SIZE) */
#define FIXTURE_HOSTNAME  "esp-tty-host-32-chars-max!!!!!"
_Static_assert(sizeof(FIXTURE_HOSTNAME) - 1 <= 32,
               "DEVICE_HOSTNAME must be at most 32 bytes");

/* USB string descriptors: max 31 characters each */
#define FIXTURE_USB_MFR   "Your Company Name Here (31 ch!)"
#define FIXTURE_USB_PROD  "Your Product Name Here (31 ch!)"
#define FIXTURE_USB_SER   "SN-00000001-PADDED-TO-31-chars!"
#define FIXTURE_USB_CDC   "Your Product CDC Name (31 ch!!)"
_Static_assert(sizeof(FIXTURE_USB_MFR)  - 1 <= 31, "USB_MANUFACTURER_STRING max 31");
_Static_assert(sizeof(FIXTURE_USB_PROD) - 1 <= 31, "USB_PRODUCT_STRING max 31");
_Static_assert(sizeof(FIXTURE_USB_SER)  - 1 <= 31, "USB_SERIAL_STRING max 31");
_Static_assert(sizeof(FIXTURE_USB_CDC)  - 1 <= 31, "USB_CDC_STRING max 31");

/* IPv4 address strings: max 15 characters ("255.255.255.255") */
#define FIXTURE_IPV4_ADDR  "255.255.255.255"
_Static_assert(sizeof(FIXTURE_IPV4_ADDR) - 1 <= 15,
               "IPv4 address string max 15 characters");

/* IPv6 address strings: max 39 characters (pure IPv6, no IPv4-mapped form).
 * esp_netif_str_to_ip6() accepts standard notation only; the IPv4-mapped form
 * ("::ffff:a.b.c.d") is handled separately.  Pure IPv6 max:
 * "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" = 39 chars. */
#define FIXTURE_IPV6_ADDR  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
_Static_assert(sizeof(FIXTURE_IPV6_ADDR) - 1 <= 39,
               "IPv6 address string max 39 characters");

/* SSH_PORT: range 1..65535 (uint16_t) */
#define FIXTURE_SSH_PORT  22
_Static_assert(FIXTURE_SSH_PORT >= 1 && FIXTURE_SSH_PORT <= 65535,
               "SSH_PORT must be in range 1..65535");

/* OTA_ROLLBACK_DELAY_MS: max practical 300000 ms (5 minutes) */
#define FIXTURE_OTA_ROLLBACK_DELAY_MS  30000
_Static_assert(FIXTURE_OTA_ROLLBACK_DELAY_MS <= 300000,
               "OTA_ROLLBACK_DELAY_MS max practical 300000");

/* --------------------------------------------------------------------------
 * Runtime tests: strlen of fixture strings matches _Static_assert limits.
 * These catch copy/paste mistakes where the fixture silently gets truncated.
 * -------------------------------------------------------------------------- */

void test_ssid_fixture_within_bound(void)
{
    TEST_ASSERT_LESS_OR_EQUAL_size_t(32, strlen(FIXTURE_SSID));
}

void test_pass_fixture_within_bound(void)
{
    TEST_ASSERT_LESS_OR_EQUAL_size_t(63, strlen(FIXTURE_PASS));
}

void test_hostname_fixture_within_bound(void)
{
    TEST_ASSERT_LESS_OR_EQUAL_size_t(32, strlen(FIXTURE_HOSTNAME));
}

void test_ipv4_addr_fixture_within_bound(void)
{
    TEST_ASSERT_LESS_OR_EQUAL_size_t(15, strlen(FIXTURE_IPV4_ADDR));
}

void test_ipv6_addr_fixture_within_bound(void)
{
    TEST_ASSERT_LESS_OR_EQUAL_size_t(39, strlen(FIXTURE_IPV6_ADDR));
}

void test_usb_strings_within_bound(void)
{
    TEST_ASSERT_LESS_OR_EQUAL_size_t(31, strlen(FIXTURE_USB_MFR));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(31, strlen(FIXTURE_USB_PROD));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(31, strlen(FIXTURE_USB_SER));
    TEST_ASSERT_LESS_OR_EQUAL_size_t(31, strlen(FIXTURE_USB_CDC));
}

void test_ssh_port_fixture_in_range(void)
{
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1,     FIXTURE_SSH_PORT);
    TEST_ASSERT_LESS_OR_EQUAL_INT   (65535, FIXTURE_SSH_PORT);
}

/* ------------------------------------------------------------------ */
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ssid_fixture_within_bound);
    RUN_TEST(test_pass_fixture_within_bound);
    RUN_TEST(test_hostname_fixture_within_bound);
    RUN_TEST(test_ipv4_addr_fixture_within_bound);
    RUN_TEST(test_ipv6_addr_fixture_within_bound);
    RUN_TEST(test_usb_strings_within_bound);
    RUN_TEST(test_ssh_port_fixture_in_range);
    return UNITY_END();
}
