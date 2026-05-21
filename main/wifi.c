/*
 * wifi.c -- Wi-Fi STA init + automatic reconnect for esp-tty
 *
 * Supports two compile-time auth modes (selected in main/config.h):
 *
 *   Default (no WIFI_USE_ENTERPRISE):
 *     WPA2/WPA3-Personal (PSK).  Set WIFI_SSID + WIFI_PASS in config.h.
 *
 *   With WIFI_USE_ENTERPRISE defined:
 *     WPA2/WPA3-Enterprise via EAP-TLS.  Set WIFI_SSID + EAP_IDENTITY in
 *     config.h, and place ca.pem / client.crt / client.key in main/certs/.
 *     See main/certs/README.md for certificate generation instructions.
 *
 * IPv4 addressing (selected in config.h):
 *
 *   Default (USE_STATIC_IPV4 not defined):
 *     DHCPv4 -- the DHCP watchdog timer keeps the client alive indefinitely.
 *
 *   With USE_STATIC_IPV4 defined:
 *     Static IPv4 -- DHCP client is stopped before the interface comes up.
 *     Requires STATIC_IPV4_ADDRESS, STATIC_IPV4_NETMASK, STATIC_IPV4_GATEWAY
 *     (all dotted-decimal strings).  Optional: STATIC_IPV4_DNS_PRIMARY,
 *     STATIC_IPV4_DNS_SECONDARY.  The DHCP watchdog is disabled automatically.
 *
 * IPv6 addressing (selected in config.h via IPV6_MODE):
 *
 *   IPV6_MODE_DISABLED              -- no IPv6 at all
 *   IPV6_MODE_SLAAC                 -- link-local + SLAAC global (default)
 *   IPV6_MODE_SLAAC_STATELESS_DHCPV6 -- SLAAC address + stateless DHCPv6 for
 *                                       options (DNS, etc.)
 *   IPV6_MODE_STATEFUL_DHCPV6       -- DHCPv6 assigns the address
 *   IPV6_MODE_STATIC                -- static global address; requires
 *                                     STATIC_IPV6_ADDRESS, STATIC_IPV6_PREFIX_LEN,
 *                                     STATIC_IPV6_GATEWAY.  Optional:
 *                                     STATIC_IPV6_DNS_PRIMARY,
 *                                     STATIC_IPV6_DNS_SECONDARY.
 *
 * Compile-time credentials come from main/config.h (gitignored).
 * Copy config.h.example -> config.h and fill in your values.
 */

#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_wifi.h"
#include "esp_system.h"

/* config.h must come before the WIFI_USE_ENTERPRISE guard below because
 * that macro is defined there (not on the command line). */
#include "wifi.h"
#ifdef BRIDGE_LOOPBACK
/* QEMU/Wokwi simulation: open AP, no password, no authmode requirement */
#define WIFI_SSID  "Wokwi-GUEST"
#define WIFI_PASS  ""
#define WIFI_AUTH_THRESHOLD  WIFI_AUTH_OPEN
#define WIFI_SAE_MODE        WPA3_SAE_PWE_UNSPECIFIED
#else
#include "config.h"   /* WIFI_SSID, WIFI_PASS, and optionally EAP_IDENTITY */
#endif

#ifdef WIFI_USE_ENTERPRISE
#include "esp_eap_client.h"
#endif

/* EAP outer/anonymous identity sent in Phase 1 of EAP-TLS (before the TLS
 * tunnel is up).  Many RADIUS servers want anonymous@<realm> here; others
 * accept the cert CN directly.  Default to "anonymous" so a Mode B or
 * Mode C build that forgets to set EAP_IDENTITY in config.h still compiles
 * -- with the obvious caveat that "anonymous" will only work if the
 * RADIUS server accepts it. */
#if defined(WIFI_USE_ENTERPRISE) || defined(WIFI_ENTERPRISE_SSID)
# ifndef EAP_IDENTITY
#  define EAP_IDENTITY  "anonymous"
# endif
#endif

/* Smart state machine (opt-in via WIFI_ENTERPRISE_SSID in config.h) */
#ifdef WIFI_ENTERPRISE_SSID
#include "esp_eap_client.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include <sys/time.h>
#include "wifi_state.h"
/* cred_store is used for the smart_configure_eaptls / wifi_mode_enterprise
 * type signatures even in Mode B + bootstrap.  scep_enroll is Mode-C-only. */
#include "cred_store.h"
# ifndef WIFI_USE_ENTERPRISE
#  include "scep_enroll.h"
# endif
#endif

/* Mutual exclusion: SCEP_NO_NTP_USE_ISSUANCE_TIME and NTP_BEFORE_EAPTLS
 * are fundamentally opposite strategies for handling the unsynced clock.
 * Defining both is a configuration error; catch it at compile time. */
#if defined(SCEP_NO_NTP_USE_ISSUANCE_TIME) && defined(NTP_BEFORE_EAPTLS) && NTP_BEFORE_EAPTLS
#error "SCEP_NO_NTP_USE_ISSUANCE_TIME and NTP_BEFORE_EAPTLS are mutually exclusive -- pick one"
#endif

#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
#include "mdns.h"
#include "mdns_dispatch.h"
#endif

#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include <time.h>
#endif

/* DHCPv6 requires the raw lwIP netif handle, obtained via
 * esp_netif_get_netif_impl().  Pull in dhcp6.h only when needed. */
#if defined(CONFIG_LWIP_IPV6) && defined(CONFIG_LWIP_IPV6_DHCP6)
#include "lwip/dhcp6.h"
#include "lwip/netif.h"
#endif

/* --------------------------------------------------------------------------
 * IPv6 mode constants
 *
 * Define these before including config.h defaults so they are available
 * regardless of whether the user has defined them.
 * -------------------------------------------------------------------------- */
#define IPV6_MODE_DISABLED                 0
#define IPV6_MODE_SLAAC                    1
#define IPV6_MODE_SLAAC_STATELESS_DHCPV6   2
#define IPV6_MODE_STATEFUL_DHCPV6          3
#define IPV6_MODE_STATIC                   4

/* --------------------------------------------------------------------------
 * Build-time knobs
 * -------------------------------------------------------------------------- */

/* Maximum consecutive reconnect attempts before wifi_init_sta() returns
 * ESP_FAIL.  After that the event handler still keeps trying indefinitely
 * (see RECONNECT_FOREVER below), so the rest of the firmware can decide
 * what to do (e.g. keep the SSH task alive for a pre-connected session).
 *
 * Default 0 = unlimited retries with NO failure signal.  Suits the
 * off-grid / unattended use case where the AP may be intermittent and
 * there is no human nearby to consume a failure log.  Set to a positive
 * integer in config.h if you want wifi_init_sta() to give up and let
 * main proceed without an IP. */
#ifndef WIFI_MAX_RETRY
#define WIFI_MAX_RETRY  0
#endif

/* DHCP watchdog: if Wi-Fi associates (L2 link is up) but no IP arrives
 * within this many seconds, restart the DHCP client (stop + start).
 * Catches the case where the AP is up but the DHCP server is unresponsive
 * -- lwIP gives up DHCP DISCOVER after a handful of retries; this loops
 * forever.  Set to 0 to disable.
 *
 * When USE_STATIC_IPV4 is defined the watchdog is skipped entirely since
 * we never run the DHCP client. */
#ifndef DHCP_RETRY_TIMEOUT_SEC
#define DHCP_RETRY_TIMEOUT_SEC  30
#endif

/* DHCP-client hostname.  Sent in the DHCP DISCOVER request, so the device
 * shows up by name in router lease tables (and is reachable as
 * <hostname>.<local-domain> if the router runs a forwarding resolver).
 * Define DEVICE_HOSTNAME in config.h to override. */
#ifndef DEVICE_HOSTNAME
#define DEVICE_HOSTNAME  "esp-tty"
#endif

/* SSH port -- used by the mDNS service advertisement.  config.h normally
 * defines this; provide a sane fallback in case it is absent (e.g. unit
 * builds that include wifi.c but not config.h). */
#ifndef SSH_PORT
#define SSH_PORT  22
#endif

#ifndef WIFI_USE_ENTERPRISE
/* -- PSK path only ------------------------------------------------------- */

/* WPA3-SAE mode.  WPA3_SAE_PWE_BOTH tries Hash-to-Element first and falls
 * back to Hunt-and-Peck -- safe for mixed WPA2/WPA3 APs. */
# ifndef WIFI_SAE_MODE
#  define WIFI_SAE_MODE   WPA3_SAE_PWE_BOTH
# endif

/* Minimum auth mode accepted during scan.  WIFI_AUTH_WPA2_PSK rejects
 * open / WEP / WPA1 APs.  Raise to WIFI_AUTH_WPA3_PSK for WPA3-only. */
# ifndef WIFI_AUTH_THRESHOLD
#  define WIFI_AUTH_THRESHOLD  WIFI_AUTH_WPA2_PSK
# endif

#else /* WIFI_USE_ENTERPRISE */
/* -- Enterprise path only ------------------------------------------------ */

/* Accept WPA2-Enterprise APs and anything stronger.
 * Use WIFI_AUTH_WPA3_ENTERPRISE to require WPA3-Enterprise-only APs. */
# ifndef WIFI_AUTH_THRESHOLD
#  define WIFI_AUTH_THRESHOLD  WIFI_AUTH_WPA2_ENTERPRISE
# endif

/* Embedded certificate linker symbols (injected by EMBED_TXTFILES in
 * main/CMakeLists.txt when WIFI_USE_ENTERPRISE is set). */
extern const uint8_t eap_ca_pem_start[]     asm("_binary_ca_pem_start");
extern const uint8_t eap_ca_pem_end[]       asm("_binary_ca_pem_end");
extern const uint8_t eap_client_crt_start[] asm("_binary_client_crt_start");
extern const uint8_t eap_client_crt_end[]   asm("_binary_client_crt_end");
extern const uint8_t eap_client_key_start[] asm("_binary_client_key_start");
extern const uint8_t eap_client_key_end[]   asm("_binary_client_key_end");

/* Minimum sane sizes for PEM blobs (bytes).  A real CA cert is >200 B;
 * these thresholds catch empty files and obviously truncated embeds at
 * boot rather than silently handing garbage to the EAP supplicant.
 * These are checked at runtime in wifi_init_sta() before any EAP calls. */
#define EAP_CA_MIN_BYTES     64
#define EAP_CRT_MIN_BYTES    64
#define EAP_KEY_MIN_BYTES    64

#endif /* WIFI_USE_ENTERPRISE */

/* --------------------------------------------------------------------------
 * IPv6 mode defaults
 *
 * When CONFIG_LWIP_IPV6 is enabled (the default), fall back to SLAAC if the
 * user hasn't chosen a mode.  When the IPv6 stack is disabled in sdkconfig,
 * default to DISABLED so no IPv6 code is compiled in.
 * -------------------------------------------------------------------------- */
#ifndef IPV6_MODE
# ifdef CONFIG_LWIP_IPV6
#  define IPV6_MODE  IPV6_MODE_SLAAC
# else
#  define IPV6_MODE  IPV6_MODE_DISABLED
# endif
#endif

/* --------------------------------------------------------------------------
 * Compile-time sanity checks for static addressing modes
 * -------------------------------------------------------------------------- */
#ifdef USE_STATIC_IPV4
# ifndef STATIC_IPV4_ADDRESS
#  error "USE_STATIC_IPV4 requires STATIC_IPV4_ADDRESS to be defined in config.h"
# endif
# ifndef STATIC_IPV4_NETMASK
#  error "USE_STATIC_IPV4 requires STATIC_IPV4_NETMASK to be defined in config.h"
# endif
# ifndef STATIC_IPV4_GATEWAY
#  error "USE_STATIC_IPV4 requires STATIC_IPV4_GATEWAY to be defined in config.h"
# endif
#endif /* USE_STATIC_IPV4 */

#if IPV6_MODE == IPV6_MODE_STATIC
# ifndef STATIC_IPV6_ADDRESS
#  error "IPV6_MODE_STATIC requires STATIC_IPV6_ADDRESS to be defined in config.h"
# endif
# ifndef STATIC_IPV6_PREFIX_LEN
#  error "IPV6_MODE_STATIC requires STATIC_IPV6_PREFIX_LEN to be defined in config.h"
# endif
# ifndef STATIC_IPV6_GATEWAY
#  error "IPV6_MODE_STATIC requires STATIC_IPV6_GATEWAY to be defined in config.h"
# endif
#endif /* IPV6_MODE_STATIC */

/* --------------------------------------------------------------------------
 * EventGroup bit definitions
 * -------------------------------------------------------------------------- */
#define WIFI_CONNECTED_BIT  BIT0   /* IP obtained              */
#define WIFI_FAIL_BIT       BIT1   /* max retries exhausted    */

/* --------------------------------------------------------------------------
 * Module-private state
 * -------------------------------------------------------------------------- */
static const char *TAG = "wifi";

static EventGroupHandle_t s_wifi_event_group;
static int                s_retry_num = 0;

/* Kept so the enterprise extension point can call esp_netif_get_ip_info()
 * from a task if needed. */
static esp_netif_t *s_sta_netif = NULL;

/* DHCP watchdog: armed on STA_CONNECTED, disarmed on STA_GOT_IP.  If it
 * fires before an IP arrives, we kick the DHCP client and re-arm.
 * Never compiled when USE_STATIC_IPV4 is defined -- static addressing
 * doesn't need a DHCP watchdog. */
#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
static TimerHandle_t s_dhcp_watchdog = NULL;

static void dhcp_watchdog_cb(TimerHandle_t t)
{
    (void)t;
    if (!s_sta_netif) return;
    ESP_LOGW(TAG, "no IP after %d s -- restarting DHCP client",
             DHCP_RETRY_TIMEOUT_SEC);
    /* dhcpc_stop() may return ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED;
     * either way, dhcpc_start() restarts the discover sequence. */
    esp_netif_dhcpc_stop(s_sta_netif);
    esp_netif_dhcpc_start(s_sta_netif);
    /* Re-arm so this loops until we get a lease. */
    xTimerStart(s_dhcp_watchdog, 0);
}
#endif

/* --------------------------------------------------------------------------
 * Static IPv4 configuration helper
 *
 * Called once after esp_netif_create_default_wifi_sta() but before
 * esp_wifi_start(), so the DHCP client is stopped before it ever sends
 * a DISCOVER.
 * -------------------------------------------------------------------------- */
#ifdef USE_STATIC_IPV4
static void apply_static_ipv4(void)
{
    esp_netif_ip_info_t ip_info = {};

    if (esp_netif_str_to_ip4(STATIC_IPV4_ADDRESS, &ip_info.ip) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid STATIC_IPV4_ADDRESS: \"%s\"", STATIC_IPV4_ADDRESS);
        return;
    }
    if (esp_netif_str_to_ip4(STATIC_IPV4_NETMASK, &ip_info.netmask) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid STATIC_IPV4_NETMASK: \"%s\"", STATIC_IPV4_NETMASK);
        return;
    }
    if (esp_netif_str_to_ip4(STATIC_IPV4_GATEWAY, &ip_info.gw) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid STATIC_IPV4_GATEWAY: \"%s\"", STATIC_IPV4_GATEWAY);
        return;
    }

    /* Stop the DHCP client before setting a static address.  It may not be
     * running yet (INIT state), but the call is harmless in that case. */
    esp_err_t err = esp_netif_dhcpc_stop(s_sta_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGW(TAG, "esp_netif_dhcpc_stop: %s", esp_err_to_name(err));
    }

    ESP_ERROR_CHECK(esp_netif_set_ip_info(s_sta_netif, &ip_info));

    ESP_LOGI(TAG, "Static IPv4: " IPSTR " / " IPSTR " gw " IPSTR,
             IP2STR(&ip_info.ip),
             IP2STR(&ip_info.netmask),
             IP2STR(&ip_info.gw));

    /* Optional static DNS servers. */
#ifdef STATIC_IPV4_DNS_PRIMARY
    {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        if (esp_netif_str_to_ip4(STATIC_IPV4_DNS_PRIMARY,
                                 &dns.ip.u_addr.ip4) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "Static DNS primary: %s", STATIC_IPV4_DNS_PRIMARY);
        } else {
            ESP_LOGW(TAG, "Invalid STATIC_IPV4_DNS_PRIMARY: \"%s\"",
                     STATIC_IPV4_DNS_PRIMARY);
        }
    }
#endif /* STATIC_IPV4_DNS_PRIMARY */

#ifdef STATIC_IPV4_DNS_SECONDARY
    {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        if (esp_netif_str_to_ip4(STATIC_IPV4_DNS_SECONDARY,
                                 &dns.ip.u_addr.ip4) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_BACKUP, &dns);
            ESP_LOGI(TAG, "Static DNS secondary: %s", STATIC_IPV4_DNS_SECONDARY);
        } else {
            ESP_LOGW(TAG, "Invalid STATIC_IPV4_DNS_SECONDARY: \"%s\"",
                     STATIC_IPV4_DNS_SECONDARY);
        }
    }
#endif /* STATIC_IPV4_DNS_SECONDARY */
}
#endif /* USE_STATIC_IPV4 */

/* --------------------------------------------------------------------------
 * IPv6 bring-up helper
 *
 * Called from the event handler when WIFI_EVENT_STA_CONNECTED fires (L2 up).
 * For SLAAC modes this triggers link-local address creation.  For static
 * mode it additionally adds the configured global address.
 * -------------------------------------------------------------------------- */
#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
static void ipv6_bring_up(void)
{
#if IPV6_MODE == IPV6_MODE_SLAAC              || \
    IPV6_MODE == IPV6_MODE_SLAAC_STATELESS_DHCPV6 || \
    IPV6_MODE == IPV6_MODE_STATEFUL_DHCPV6    || \
    IPV6_MODE == IPV6_MODE_STATIC
    /* Create a link-local address (fe80::) for all IPv6 modes.  This is
     * mandatory before any other IPv6 addresses can be assigned. */
    esp_err_t err = esp_netif_create_ip6_linklocal(s_sta_netif);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_netif_create_ip6_linklocal: %s",
                 esp_err_to_name(err));
    }
#endif

#if IPV6_MODE == IPV6_MODE_STATIC
    /* Add the statically configured global unicast address. */
    esp_ip6_addr_t addr6 = {};
    if (esp_netif_str_to_ip6(STATIC_IPV6_ADDRESS, &addr6) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid STATIC_IPV6_ADDRESS: \"%s\"",
                 STATIC_IPV6_ADDRESS);
        return;
    }
    esp_err_t aerr = esp_netif_add_ip6_address(s_sta_netif, addr6, true);
    if (aerr != ESP_OK) {
        ESP_LOGW(TAG, "esp_netif_add_ip6_address: %s", esp_err_to_name(aerr));
    } else {
        ESP_LOGI(TAG, "Static IPv6: " IPV6STR "/%d",
                 IPV62STR(addr6), (int)STATIC_IPV6_PREFIX_LEN);
    }

    /* Optional static IPv6 DNS. */
#ifdef STATIC_IPV6_DNS_PRIMARY
    {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V6;
        if (esp_netif_str_to_ip6(STATIC_IPV6_DNS_PRIMARY,
                                 &dns.ip.u_addr.ip6) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "Static IPv6 DNS primary: %s",
                     STATIC_IPV6_DNS_PRIMARY);
        } else {
            ESP_LOGW(TAG, "Invalid STATIC_IPV6_DNS_PRIMARY: \"%s\"",
                     STATIC_IPV6_DNS_PRIMARY);
        }
    }
#endif /* STATIC_IPV6_DNS_PRIMARY */

#ifdef STATIC_IPV6_DNS_SECONDARY
    {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V6;
        if (esp_netif_str_to_ip6(STATIC_IPV6_DNS_SECONDARY,
                                 &dns.ip.u_addr.ip6) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_BACKUP, &dns);
            ESP_LOGI(TAG, "Static IPv6 DNS secondary: %s",
                     STATIC_IPV6_DNS_SECONDARY);
        } else {
            ESP_LOGW(TAG, "Invalid STATIC_IPV6_DNS_SECONDARY: \"%s\"",
                     STATIC_IPV6_DNS_SECONDARY);
        }
    }
#endif /* STATIC_IPV6_DNS_SECONDARY */
#endif /* IPV6_MODE_STATIC */

#if (IPV6_MODE == IPV6_MODE_SLAAC_STATELESS_DHCPV6 || \
     IPV6_MODE == IPV6_MODE_STATEFUL_DHCPV6) && \
    defined(CONFIG_LWIP_IPV6_DHCP6)
    /* Enable DHCPv6.  dhcp6_enable_stateless/stateful operate on the raw
     * lwIP netif pointer, not the esp_netif handle.  We obtain it via
     * esp_netif_get_netif_impl() which returns a (struct netif *). */
    struct netif *lwip_netif =
        (struct netif *)esp_netif_get_netif_impl(s_sta_netif);
    if (lwip_netif) {
# if IPV6_MODE == IPV6_MODE_SLAAC_STATELESS_DHCPV6
        err_t derr = dhcp6_enable_stateless(lwip_netif);
        if (derr != ERR_OK) {
            ESP_LOGW(TAG, "dhcp6_enable_stateless failed: %d", (int)derr);
        } else {
            ESP_LOGI(TAG, "DHCPv6 stateless (options) enabled");
        }
# elif IPV6_MODE == IPV6_MODE_STATEFUL_DHCPV6
        err_t derr = dhcp6_enable_stateful(lwip_netif);
        if (derr != ERR_OK) {
            ESP_LOGW(TAG, "dhcp6_enable_stateful failed: %d", (int)derr);
        } else {
            ESP_LOGI(TAG, "DHCPv6 stateful enabled");
        }
# endif
    } else {
        ESP_LOGW(TAG, "esp_netif_get_netif_impl returned NULL -- DHCPv6 not started");
    }
#endif /* DHCPv6 modes */
}
#endif /* IPV6_MODE != IPV6_MODE_DISABLED */

/* --------------------------------------------------------------------------
 * NTP defaults
 * -------------------------------------------------------------------------- */
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)

# ifndef NTP_SERVERS
#  define NTP_SERVERS  "pool.ntp.org"
# endif

# ifndef NTP_TIMEZONE
#  define NTP_TIMEZONE  "UTC0"
# endif

# ifndef NTP_SYNC_TIMEOUT_SEC
#  define NTP_SYNC_TIMEOUT_SEC  30
# endif

/* Max TZ string length accepted by setenv (caps before writing to env). */
# define NTP_TZ_MAX_LEN  64

static volatile bool s_ntp_started = false;

static void ntp_sync_cb(struct timeval *tv)
{
    (void)tv;
    time_t now = time(NULL);
    struct tm t;
    gmtime_r(&now, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t);
    ESP_LOGI(TAG, "NTP synced: %s", buf);
}

static void ntp_start_task(void *pvParameters)
{
    (void)pvParameters;

    const char *const servers[] = { NTP_SERVERS };
    const size_t n_servers = sizeof(servers) / sizeof(servers[0]);

    /* Log the server list so it's visible in the boot log. */
    for (size_t i = 0; i < n_servers; i++) {
        ESP_LOGI(TAG, "NTP server[%u]: %s", (unsigned)i, servers[i]);
    }

    esp_sntp_config_t cfg = {
        .smooth_sync               = false,
        .server_from_dhcp          = false,
        .wait_for_sync             = true,
        .start                     = true,
        .sync_cb                   = ntp_sync_cb,
        .renew_servers_after_new_IP = false,
        .ip_event_to_renew         = IP_EVENT_STA_GOT_IP,
        .index_of_first_server     = 0,
        .num_of_servers            = n_servers,
    };
    for (size_t i = 0; i < n_servers && i < CONFIG_LWIP_SNTP_MAX_SERVERS; i++) {
        cfg.servers[i] = servers[i];
    }

    esp_err_t err = esp_netif_sntp_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_sntp_init failed: %s", esp_err_to_name(err));
        s_ntp_started = false;
        vTaskDelete(NULL);
        return;
    }

    /* Apply timezone before waiting so any logged timestamps are local. */
    char tz_buf[NTP_TZ_MAX_LEN + 1];
    snprintf(tz_buf, sizeof(tz_buf), "%s", NTP_TIMEZONE);
    setenv("TZ", tz_buf, 1);
    tzset();

    /* Wait up to NTP_SYNC_TIMEOUT_SEC; log progress, then background. */
    TickType_t deadline = xTaskGetTickCount() +
                          pdMS_TO_TICKS((uint32_t)NTP_SYNC_TIMEOUT_SEC * 1000u);
    while (xTaskGetTickCount() < deadline) {
        esp_err_t wret = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(5000));
        if (wret == ESP_OK) {
            /* sync_cb already logged the timestamp */
            vTaskDelete(NULL);
            return;
        }
        ESP_LOGI(TAG, "NTP: waiting for sync ...");
    }
    ESP_LOGW(TAG, "NTP: sync not complete within %d s -- continuing in background",
             NTP_SYNC_TIMEOUT_SEC);

    vTaskDelete(NULL);
}

static void ntp_dispatch_start(void)
{
    if (s_ntp_started) return;
    s_ntp_started = true;

    BaseType_t ret = xTaskCreate(ntp_start_task, "ntp_start",
                                 4096, NULL,
                                 tskIDLE_PRIORITY + 1, NULL);
    if (ret != pdPASS) {
        ESP_LOGW(TAG, "xTaskCreate(ntp_start_task) failed -- NTP not started");
        s_ntp_started = false;
    }
}

#endif /* !BRIDGE_LOOPBACK && NTP_ENABLE */

/* --------------------------------------------------------------------------
 * mDNS -- hostname advertisement and _ssh._tcp service record
 *
 * Runs as a short-lived FreeRTOS task so the event handler (which runs in
 * the system event task with a limited stack) is not burdened with mDNS init.
 * The task deletes itself on completion or on any fatal error.
 *
 * Off by default.  Define MDNS_ENABLE in config.h to advertise the device.
 * Always compiled out under BRIDGE_LOOPBACK -- the Wokwi/QEMU simulation has
 * no real radio and no use for mDNS.
 * -------------------------------------------------------------------------- */
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)

static void mdns_start_task(void *pvParameters)
{
    (void)pvParameters;

    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mdns_init failed: %s", esp_err_to_name(err));
        vTaskDelete(NULL);
        return;
    }

    err = mdns_hostname_set(DEVICE_HOSTNAME);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_hostname_set(\"%s\") failed: %s",
                 DEVICE_HOSTNAME, esp_err_to_name(err));
        /* Non-fatal -- continue so the service record is still published. */
    }

    err = mdns_service_add(NULL, "_ssh", "_tcp", SSH_PORT, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mdns_service_add(_ssh._tcp) failed: %s",
                 esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "mDNS started: hostname=%s.local, advertising _ssh._tcp port %d",
             DEVICE_HOSTNAME, SSH_PORT);

    vTaskDelete(NULL);
}

static int mdns_xtask_create(void)
{
    BaseType_t ret = xTaskCreate(mdns_start_task, "mdns_start",
                                 4096, NULL,
                                 tskIDLE_PRIORITY + 1, NULL);
    return (ret == pdPASS) ? 1 : 0;
}

static void mdns_dispatch_start(void)
{
    if (!mdns_dispatch_once(mdns_xtask_create)) {
        ESP_LOGW(TAG, "xTaskCreate(mdns_start_task) failed -- mDNS not started");
    }
}

#endif /* !BRIDGE_LOOPBACK && MDNS_ENABLE */

/* --------------------------------------------------------------------------
 * Event handler
 *
 * Runs in the system event task context (stack ~3 kB).  Keep it lean.
 * -------------------------------------------------------------------------- */
static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t          event_id,
                               void            *event_data)
{
    if (event_base == WIFI_EVENT) {

        if (event_id == WIFI_EVENT_STA_START) {
            /* Driver is up -- kick off the first connection attempt.  Read
             * the actual SSID from the driver rather than hard-coding
             * WIFI_SSID; in Mode B+/C the active config may be the
             * enterprise SSID, not the PSK bootstrap one. */
            wifi_config_t cur = {0};
            const char *ssid_str = WIFI_SSID;  /* fallback */
            if (esp_wifi_get_config(WIFI_IF_STA, &cur) == ESP_OK
                && cur.sta.ssid[0] != '\0') {
                ssid_str = (const char *)cur.sta.ssid;
            }
            ESP_LOGI(TAG, "STA started, connecting to \"%s\" ...", ssid_str);
            esp_wifi_connect();

        } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
            /* L2 association succeeded.
             *
             * Static IPv4: stop the DHCP client (which may have auto-started
             * when the interface came up) and apply the static address NOW so
             * the netif is fully configured before we signal "connected".
             * IP_EVENT_STA_GOT_IP will not fire via DHCP; we signal the event
             * group ourselves below after setting the address.
             *
             * DHCPv4: arm the watchdog so a stuck DHCP server doesn't leave
             * us without an IP forever. */
#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
            if (s_dhcp_watchdog) {
                xTimerChangePeriod(s_dhcp_watchdog,
                                   pdMS_TO_TICKS(DHCP_RETRY_TIMEOUT_SEC * 1000),
                                   0);
                xTimerStart(s_dhcp_watchdog, 0);
            }
#endif

#ifdef USE_STATIC_IPV4
            /* Apply static address at L2-connect time so the routing table
             * is populated before we signal success. */
            apply_static_ipv4();
            /* Log and signal immediately -- no IP event will follow. */
            {
                esp_netif_ip_info_t ip;
                if (esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK) {
                    ESP_LOGI(TAG, "IP address : " IPSTR, IP2STR(&ip.ip));
                    ESP_LOGI(TAG, "Netmask    : " IPSTR, IP2STR(&ip.netmask));
                    ESP_LOGI(TAG, "Gateway    : " IPSTR, IP2STR(&ip.gw));
                }
            }
            s_retry_num = 0;
            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
            mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
            ntp_dispatch_start();
#endif
#endif /* USE_STATIC_IPV4 */

            /* Bring up IPv6 (SLAAC / DHCPv6 / static) now that L2 is up. */
#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
            ipv6_bring_up();
#endif

        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            wifi_event_sta_disconnected_t *ev =
                (wifi_event_sta_disconnected_t *)event_data;

            /* Clear the connected bit so callers that poll it see the drop. */
            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
            /* L2 link is down; pause the watchdog until we re-associate. */
            if (s_dhcp_watchdog) xTimerStop(s_dhcp_watchdog, 0);
#endif

            const bool infinite = (WIFI_MAX_RETRY == 0);
            if (infinite || s_retry_num < WIFI_MAX_RETRY) {
                s_retry_num++;
                if (infinite) {
                    ESP_LOGW(TAG, "disconnected (reason %d), retry %d (infinite)",
                             ev->reason, s_retry_num);
                } else {
                    ESP_LOGW(TAG, "disconnected (reason %d), retry %d/%d",
                             ev->reason, s_retry_num, WIFI_MAX_RETRY);
                }
                esp_wifi_connect();
            } else {
                /* Signal permanent failure to wifi_init_sta()'s wait. */
                xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                ESP_LOGE(TAG, "gave up after %d retries (reason %d)",
                         WIFI_MAX_RETRY, ev->reason);

                /* RECONNECT_FOREVER: keep retrying even after signalling
                 * failure so we recover if the AP comes back later.
                 * Remove the call below if you want hard-stop semantics. */
                esp_wifi_connect();
            }
        }

    } else if (event_base == IP_EVENT) {

        if (event_id == IP_EVENT_STA_GOT_IP) {
#ifndef USE_STATIC_IPV4
            /* DHCPv4 path: print the assigned address and signal ready.
             * Under static IP this event may still fire (esp-netif raises it
             * when the netif IP changes), but we already logged and signalled
             * in the STA_CONNECTED handler, so skip it to avoid duplicates. */
            ip_event_got_ip_t *ev = (ip_event_got_ip_t *)event_data;

            /* ----------------------------------------------------------------
             * Print the DHCP-assigned IP to the UART log -- the primary
             * discovery mechanism for v1 (no mDNS).  SSH task can start now.
             * ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "IP address : " IPSTR, IP2STR(&ev->ip_info.ip));
            ESP_LOGI(TAG, "Netmask    : " IPSTR, IP2STR(&ev->ip_info.netmask));
            ESP_LOGI(TAG, "Gateway    : " IPSTR, IP2STR(&ev->ip_info.gw));

#if DHCP_RETRY_TIMEOUT_SEC > 0
            /* DHCP succeeded -- disarm the watchdog. */
            if (s_dhcp_watchdog) xTimerStop(s_dhcp_watchdog, 0);
#endif

            s_retry_num = 0;
            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
            mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
            ntp_dispatch_start();
#endif
#endif /* !USE_STATIC_IPV4 */

#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
        } else if (event_id == IP_EVENT_GOT_IP6) {
            ip_event_got_ip6_t *ev6 = (ip_event_got_ip6_t *)event_data;
            ESP_LOGI(TAG, "IPv6 address: " IPV6STR,
                     IPV62STR(ev6->ip6_info.ip));
#endif /* IPV6_MODE != IPV6_MODE_DISABLED */
        }
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

esp_err_t wifi_init_sta(void)
{
#ifdef BRIDGE_LOOPBACK
    /* QEMU/Wokwi: no WiFi radio -- init the TCP/IP stack only so LwIP
     * sockets work, then return immediately (SSH server binds to 0.0.0.0). */
    ESP_LOGI(TAG, "BRIDGE_LOOPBACK: skipping WiFi, init netif only");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();
    return ESP_OK;
#endif

    /* 1. Create the EventGroup used to synchronise with app_main / ssh_task. */
    s_wifi_event_group = xEventGroupCreate();
    configASSERT(s_wifi_event_group);

#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
    /* Create the DHCP watchdog as a one-shot timer; the event handler
     * arms it on WIFI_EVENT_STA_CONNECTED, the callback re-arms it after
     * each kick.  Period set here as a safe initial value; actual period
     * is set via xTimerChangePeriod when armed. */
    s_dhcp_watchdog = xTimerCreate(
        "dhcp_wd",
        pdMS_TO_TICKS(DHCP_RETRY_TIMEOUT_SEC * 1000),
        pdFALSE,    /* one-shot; callback re-arms manually */
        NULL,
        dhcp_watchdog_cb);
    if (!s_dhcp_watchdog) {
        ESP_LOGW(TAG, "Failed to create DHCP watchdog timer -- DHCP "
                      "retries will rely on lwIP's default behaviour");
    }
#endif

    /* 2. Initialise the TCP/IP stack and create the default event loop.
     *    Order matters: esp_netif_init() before esp_event_loop_create_default()
     *    before esp_netif_create_default_wifi_sta(). */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_sta_netif = esp_netif_create_default_wifi_sta();
    configASSERT(s_sta_netif);

    /* Hostname sent in DHCP DISCOVER; lets the router/DNS reach us by name.
     * Must be set after netif creation but before the DHCP client runs
     * (which happens implicitly once we get an IP). */
    esp_err_t herr = esp_netif_set_hostname(s_sta_netif, DEVICE_HOSTNAME);
    if (herr == ESP_OK)
        ESP_LOGI(TAG, "DHCP hostname: %s", DEVICE_HOSTNAME);
    else
        ESP_LOGW(TAG, "esp_netif_set_hostname(\"%s\") failed: %s",
                 DEVICE_HOSTNAME, esp_err_to_name(herr));

    /* 3. Initialise the Wi-Fi driver with the default (ROM-based) config. */
    wifi_init_config_t driver_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&driver_cfg));

#ifdef WIFI_MAC_BYTES
    /* Override the factory-burned MAC.
     *
     * Constraint: ESP-IDF only accepts a locally-administered unicast MAC
     * unless a custom MAC has also been burned into eFuse -- which this
     * project never does.  "Locally-administered unicast" means:
     *   - first octet bit 1 = 1  (locally administered)
     *   - first octet bit 0 = 0  (unicast, not multicast)
     * Equivalently: the low nibble of byte 0 is one of 2, 6, A, or E.
     * Valid first-byte prefixes: 02, 06, 0A, 0E, 12, 16, 1A, 1E, 22, 26, ...
     *
     * We pre-validate here so a wrong MAC produces a clear error instead
     * of the generic ESP_ERR_INVALID_ARG that esp_wifi_set_mac returns. */
    {
        const uint8_t custom_mac[6] = WIFI_MAC_BYTES;
        if ((custom_mac[0] & 0x03) != 0x02) {
            ESP_LOGE(TAG,
                     "WIFI_MAC_BYTES first byte 0x%02x is not a locally-"
                     "administered unicast MAC. The low nibble of byte 0 "
                     "must be 2, 6, A, or E (e.g. 02, 06, 0A, 0E, 12, ...). "
                     "Falling back to the factory MAC.",
                     custom_mac[0]);
        } else {
            esp_err_t merr = esp_wifi_set_mac(WIFI_IF_STA,
                                              (uint8_t *)custom_mac);
            if (merr != ESP_OK) {
                ESP_LOGW(TAG,
                         "esp_wifi_set_mac failed: %s -- falling back to "
                         "factory MAC", esp_err_to_name(merr));
            }
        }
    }
#endif

    /* Log the active MAC (factory or overridden) so it's easy to find for
     * static DHCP reservations / firewall rules. */
    {
        uint8_t active_mac[6];
        if (esp_wifi_get_mac(WIFI_IF_STA, active_mac) == ESP_OK)
            ESP_LOGI(TAG, "WiFi MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                     active_mac[0], active_mac[1], active_mac[2],
                     active_mac[3], active_mac[4], active_mac[5]);
    }

    /* 4. Register event handlers.
     *    instance_any_id  -> all WIFI_EVENT sub-events (start, disconnect, ...)
     *    instance_got_ip  -> IP_EVENT_STA_GOT_IP only
     *    instance_got_ip6 -> IP_EVENT_GOT_IP6 (when IPv6 is enabled) */
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID,
        &wifi_event_handler, NULL, &instance_any_id));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP,
        &wifi_event_handler, NULL, &instance_got_ip));

#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
    esp_event_handler_instance_t instance_got_ip6;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_GOT_IP6,
        &wifi_event_handler, NULL, &instance_got_ip6));
#endif

    /* 5. Build the STA config.
     *
     *    Common fields:
     *      .ssid              -- target network name (from config.h)
     *      .threshold.authmode-- lowest auth mode accepted during scan
     *      .pmf_cfg           -- Protected Management Frames
     *
     *    PSK-only fields (.password, .sae_pwe_h2e) are omitted in enterprise
     *    mode; the EAP credentials are set via esp_eap_client_* below.
     *    See config.h.example for how to switch between the two modes.
     */
#ifndef WIFI_USE_ENTERPRISE
    /* -- WPA2/WPA3-Personal (PSK) ---------------------------------------- */
    wifi_config_t wifi_config = {
        .sta = {
            .ssid     = WIFI_SSID,
            .password = WIFI_PASS,

            /* Reject APs weaker than WPA2-PSK.
             * Bump to WIFI_AUTH_WPA3_PSK for WPA3-only environments. */
            .threshold.authmode = WIFI_AUTH_THRESHOLD,

            /* SAE (WPA3): try Hash-to-Element, fall back to Hunt-and-Peck. */
            .sae_pwe_h2e = WIFI_SAE_MODE,

            /* PMF: advertise support (required for WPA3),
             * but not mandatory so WPA2-only APs still work. */
            .pmf_cfg = {
                .capable  = true,
                .required = false,
            },
        },
    };
#else /* WIFI_USE_ENTERPRISE */
    /* -- WPA2/WPA3-Enterprise (EAP-TLS) --------------------------------- */
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,

            /* Reject APs weaker than WPA2-Enterprise. */
            .threshold.authmode = WIFI_AUTH_THRESHOLD,

            /* PMF is mandatory for WPA3-Enterprise.  Set required=true here
             * so WPA3-Enterprise APs work; WPA2-Enterprise APs also honour
             * PMF when capable.  If your AP is WPA2-Enterprise-only and
             * doesn't support PMF, change required to false. */
            .pmf_cfg = {
                .capable  = true,
                .required = true,
            },

            /* sae_pwe_h2e is SAE-specific (PSK); not used in enterprise. */
        },
    };
#endif /* WIFI_USE_ENTERPRISE */

    /* 6. Apply mode and config. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

#ifdef WIFI_USE_ENTERPRISE
    /* 6b. Configure EAP-TLS credentials.
     *
     *     Call sequence matters: identity -> CA cert -> client cert+key ->
     *     enterprise_enable -> start.  All calls must precede esp_wifi_start().
     *
     *     Identity: outer/phase-1 identity sent before the TLS tunnel is up.
     *     Many RADIUS servers want "anonymous@realm" here for privacy.
     *     Inner identity is derived from the client certificate CN by the
     *     RADIUS server -- no esp_eap_client_set_username() needed for EAP-TLS.
     *
     *     Sanity-check the embedded blobs before handing them to the EAP
     *     supplicant.  If cert files were empty or truncated at build time the
     *     linker symbols still exist but the size will be wrong; catch that
     *     at boot rather than getting a cryptic EAP negotiation failure.
     */
    configASSERT((eap_ca_pem_end  - eap_ca_pem_start)     >= EAP_CA_MIN_BYTES);
    configASSERT((eap_client_crt_end - eap_client_crt_start) >= EAP_CRT_MIN_BYTES);
    configASSERT((eap_client_key_end - eap_client_key_start) >= EAP_KEY_MIN_BYTES);

    ESP_LOGI(TAG, "Configuring EAP-TLS (identity: %s)", EAP_IDENTITY);

    ESP_ERROR_CHECK(esp_eap_client_set_identity(
        (const unsigned char *)EAP_IDENTITY, strlen(EAP_IDENTITY)));

    /* CA certificate: validates the RADIUS server's certificate.
     * Embedded via EMBED_TXTFILES -- buffer is null-terminated PEM.
     * Length includes the null terminator (end - start). */
    ESP_ERROR_CHECK(esp_eap_client_set_ca_cert(
        eap_ca_pem_start,
        eap_ca_pem_end - eap_ca_pem_start));

    /* Client certificate + private key for mutual TLS authentication.
     * NULL password = unencrypted key.  To use an encrypted key, define
     * EAP_KEY_PASSWORD in config.h and pass it here. */
    ESP_ERROR_CHECK(esp_eap_client_set_certificate_and_key(
        eap_client_crt_start,
        eap_client_crt_end - eap_client_crt_start,
        eap_client_key_start,
        eap_client_key_end - eap_client_key_start,
        NULL, 0));

#ifdef EAP_DISABLE_TIME_CHECK
    /* Skip certificate expiry validation.  Only use this during development
     * when the device lacks SNTP / a real-time clock.  Remove for production
     * and configure SNTP before calling wifi_init_sta() instead. */
    ESP_LOGW(TAG, "EAP time check DISABLED -- not safe for production");
    ESP_ERROR_CHECK(esp_eap_client_set_disable_time_check(true));
#endif

    /* EAP-TLS only: with just cert+key configured (no username/password),
     * the IDF 5.4.1 supplicant auto-selects EAP-TLS.  An explicit
     * method-restriction API existed in older IDFs but was removed. */
    ESP_ERROR_CHECK(esp_wifi_sta_enterprise_enable());
#endif /* WIFI_USE_ENTERPRISE */

    /* 7. Start the Wi-Fi driver.
     *    WIFI_EVENT_STA_START fires after this returns, triggering
     *    esp_wifi_connect() in the event handler above. */
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta complete, waiting for IP ...");

    /* 8. Block until connected+IP or retry-limit exhausted.
     *    BRIDGE_LOOPBACK uses a 10 s timeout so QEMU/CI doesn't hang forever
     *    waiting for a WiFi radio that doesn't exist. */
#ifdef BRIDGE_LOOPBACK
#define WIFI_WAIT_TICKS  pdMS_TO_TICKS(10000)
#else
#define WIFI_WAIT_TICKS  portMAX_DELAY
#endif
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,   /* do not clear on exit */
        pdFALSE,   /* wait for either bit  */
        WIFI_WAIT_TICKS);

    /* 9. Deregister the one-shot instances; the handler stays registered
     *    for reconnect events from the persistent WIFI_EVENT registration. */
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));

#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
    /* Note: do NOT unregister instance_got_ip6 -- IPv6 addresses may be
     * acquired long after the initial connection (RA solicitation, DHCPv6
     * lease) and we want to log them whenever they arrive.  The event
     * handler is lightweight (just an ESP_LOGI call) so keeping it is safe. */
    (void)instance_got_ip6;
#endif

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to \"%s\"", WIFI_SSID);
        return ESP_OK;
    }

    if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "failed to connect to \"%s\"", WIFI_SSID);
        return ESP_FAIL;
    }

    /* Should never reach here (portMAX_DELAY wait). */
    ESP_LOGE(TAG, "unexpected event group state 0x%lx", (unsigned long)bits);
    return ESP_FAIL;
}

/* ==========================================================================
 * wifi_init_smart() -- two-network boot-time state machine
 *
 * Available only when WIFI_ENTERPRISE_SSID is defined in config.h.
 *
 * High-level flow:
 *   1. Read NVS credential store.
 *   2. Decide: bootstrap-full, bootstrap-NTP-only, or enterprise.
 *   3a. ENTERPRISE: connect EAP-TLS; success -> done; fail -> loop.
 *   3b. BOOTSTRAP_NTP_ONLY: connect PSK, sync NTP, disconnect, go to 2.
 *   3c. BOOTSTRAP_FULL: connect PSK, sync NTP, check cert expiry, run SCEP
 *       if needed, reboot after successful enrollment.
 *
 * Driver lifecycle:
 *   - esp_wifi_init() is called once.
 *   - Between network switches: esp_wifi_stop() -> reconfigure -> start().
 *   - esp_wifi_deinit() is never called (too destructive).
 *   - Enterprise enable/disable wrappers guard the EAP supplicant state.
 *
 * See wifi_state.h for the pure decision function and its truth table.
 * ========================================================================== */

#ifdef WIFI_ENTERPRISE_SSID

/* --------------------------------------------------------------------------
 * Smart-mode tunables
 * -------------------------------------------------------------------------- */

/* How many enterprise attempts before falling back to bootstrap to re-enroll.
 * 0 = unlimited (never fall back due to attempt count alone). */
#ifndef WIFI_ENTERPRISE_RETRY_MAX
# define WIFI_ENTERPRISE_RETRY_MAX  5
#endif

/* Seconds to wait for an IP in enterprise mode before declaring failure. */
#ifndef EAPTLS_HANDSHAKE_TIMEOUT_SEC
# define EAPTLS_HANDSHAKE_TIMEOUT_SEC  60
#endif

/* Cert is considered "expired" when fewer than this many seconds remain.
 * Default 86400 = 24 hours (early renewal window so overnight expiry doesn't
 * bite).  Override in config.h if your CA issues short-lived certs. */
#ifndef CERT_REENROLL_THRESHOLD_SEC
# define CERT_REENROLL_THRESHOLD_SEC  86400
#endif

/* Seconds to wait for NTP sync on the bootstrap network. */
#ifndef BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC
# define BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC  30
#endif

/* Default NTP_BEFORE_EAPTLS to 1 when NTP_ENABLE is set and a bootstrap PSK
 * network is available (WIFI_SSID + WIFI_PASS); otherwise keep 0 so existing
 * Mode C/B+ configs that have not explicitly set the macro are unaffected
 * unless they also define NTP_ENABLE.  Users can override to 0 to opt out. */
#ifndef NTP_BEFORE_EAPTLS
# if defined(NTP_ENABLE) && defined(WIFI_SSID) && defined(WIFI_PASS)
#  define NTP_BEFORE_EAPTLS 1
# else
#  define NTP_BEFORE_EAPTLS 0
# endif
#endif

/* MIN_PLAUSIBLE_EPOCH is defined in wifi_state.h (already included above). */

/* --------------------------------------------------------------------------
 * forward declaration for ntp_dispatch_start used in smart mode below.
 * The function is already defined above under !BRIDGE_LOOPBACK && NTP_ENABLE.
 * For the smart path we need our own lightweight NTP sync that BLOCKS
 * (unlike the background ntp_dispatch_start which tasks and returns).
 * -------------------------------------------------------------------------- */

/* Bring up PSK, wait for IP, call on_ip(), stop WiFi.
 *
 * The caller is responsible for having called esp_wifi_init() once already.
 * This function does not call esp_wifi_init() or esp_wifi_deinit().
 *
 * Returns the return value of on_ip() on success, or ESP_FAIL on connection
 * failure. */
static esp_err_t wifi_mode_psk(const char *ssid,
                                const char *pass,
                                esp_err_t (*on_ip)(void))
{
    ESP_LOGI(TAG, "[smart] connecting to bootstrap PSK network \"%s\"", ssid);

    /* Disable enterprise supplicant if it was previously active. */
    esp_wifi_sta_enterprise_disable();

    wifi_config_t cfg = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .sae_pwe_h2e        = WPA3_SAE_PWE_BOTH,
            .pmf_cfg = {
                .capable  = true,
                .required = false,
            },
        },
    };
    /* ssid and pass may be up to 32 / 64 bytes; use strncpy to be safe. */
    strncpy((char *)cfg.sta.ssid,     ssid, sizeof(cfg.sta.ssid) - 1);
    strncpy((char *)cfg.sta.password, pass, sizeof(cfg.sta.password) - 1);

    /* Reset event-group bits from any previous round. */
    xEventGroupClearBits(s_wifi_event_group,
                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    s_retry_num = 0;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Wait for IP or failure.  WIFI_MAX_RETRY=0 means infinite here too. */
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        portMAX_DELAY);

    if (!(bits & WIFI_CONNECTED_BIT)) {
        ESP_LOGE(TAG, "[smart] PSK connect to \"%s\" failed", ssid);
        esp_wifi_stop();
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "[smart] PSK connected to \"%s\"", ssid);
    esp_err_t result = on_ip ? on_ip() : ESP_OK;

    esp_wifi_stop();
    return result;
}

/* Synchronously wait for NTP sync up to BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC.
 * Returns true if clock looks sane after the wait. */
static bool smart_ntp_wait_sync(void)
{
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
    ESP_LOGI(TAG, "[smart] waiting up to %d s for NTP sync ...",
             BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC);

    /* If SNTP has not been inited yet, start it now. */
    const char *const servers[] = { NTP_SERVERS };
    const size_t n_servers = sizeof(servers) / sizeof(servers[0]);

    esp_sntp_config_t cfg = {
        .smooth_sync                = false,
        .server_from_dhcp           = false,
        .wait_for_sync              = true,
        .start                      = true,
        .sync_cb                    = NULL,
        .renew_servers_after_new_IP = false,
        .ip_event_to_renew          = IP_EVENT_STA_GOT_IP,
        .index_of_first_server      = 0,
        .num_of_servers             = n_servers,
    };
    for (size_t i = 0; i < n_servers && i < CONFIG_LWIP_SNTP_MAX_SERVERS; i++) {
        cfg.servers[i] = servers[i];
    }

    /* Deinit any previous SNTP singleton from an earlier bootstrap pass so
     * sync_wait sees a fresh state machine on this attempt.  Otherwise it
     * can return ESP_ERR_TIMEOUT even after the sntp callback has set the
     * clock, leading to a stuck wait loop. */
    esp_netif_sntp_deinit();

    esp_err_t init_err = esp_netif_sntp_init(&cfg);
    if (init_err != ESP_OK && init_err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "[smart] esp_netif_sntp_init: %s",
                 esp_err_to_name(init_err));
        return false;
    }

    TickType_t deadline = xTaskGetTickCount() +
        pdMS_TO_TICKS((uint32_t)BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC * 1000u);
    while (xTaskGetTickCount() < deadline) {
        esp_err_t wait_err = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(5000));
        if (wait_err == ESP_OK) {
            break;
        }
        /* esp_netif_sntp_sync_wait can return ESP_ERR_TIMEOUT even after the
         * sntp callback already set the clock (singleton-state edge case
         * after re-init).  Use a real-time-of-day check as a faster exit. */
        if (time(NULL) >= MIN_PLAUSIBLE_EPOCH) {
            break;
        }
        ESP_LOGI(TAG, "[smart] NTP: still waiting (%s) ...",
                 esp_err_to_name(wait_err));
        /* Defensive floor: if sync_wait returned faster than the requested
         * timeout (e.g. due to an internal error state), avoid spinning
         * the CPU and spamming the log. */
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
#else
    /* NTP not enabled or loopback build -- skip. */
#endif /* NTP_ENABLE */

    time_t now = time(NULL);
    bool synced = (now >= MIN_PLAUSIBLE_EPOCH);
    ESP_LOGI(TAG, "[smart] NTP sync check: epoch=%lld plausible=%s",
             (long long)now, synced ? "yes" : "no");
    return synced;
}

/* on_ip callback for bootstrap NTP-only pass: sync NTP, return. */
static esp_err_t smart_on_ip_ntp_only(void)
{
    smart_ntp_wait_sync();
    return ESP_OK;  /* Always return OK; caller checks time() afterwards. */
}

/* on_ip callback for bootstrap full pass (Mode C only): sync NTP (unless
 * no-NTP mode), check cert, enroll via SCEP.
 *
 * In SCEP_NO_NTP_USE_ISSUANCE_TIME mode NTP is skipped entirely; after a
 * successful enrollment the issued cert's NotBefore field is used to set the
 * local clock before rebooting into enterprise mode. */
#ifndef WIFI_USE_ENTERPRISE
static esp_err_t smart_on_ip_full(void)
{
#ifdef SCEP_NO_NTP_USE_ISSUANCE_TIME
    /* No-NTP mode: skip SNTP entirely.  We'll set the clock from the cert's
     * NotBefore after enrollment below. */
    ESP_LOGI(TAG, "[smart] no-NTP mode: skipping SNTP sync");
#else
    bool synced = smart_ntp_wait_sync();
    (void)synced;

    /* Check cert expiry from NVS (reload after NTP so time is correct).
     * Heap-allocate the cred_store_t (~14 KB) to avoid overflowing
     * whatever task stack this callback runs on. */
    cred_store_t *creds = heap_caps_calloc(1, sizeof(cred_store_t),
                                           MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    if (!creds) {
        ESP_LOGE(TAG, "[smart] full: failed to allocate cred_store_t");
        return ESP_FAIL;
    }
    bool cert_present = (cred_store_load(creds) == ESP_OK);
    bool cert_expired = false;

    if (cert_present) {
        time_t now = time(NULL);
        if (now >= MIN_PLAUSIBLE_EPOCH) {
            time_t expiry = (time_t)creds->not_after;
            cert_expired = (expiry - now) < (time_t)CERT_REENROLL_THRESHOLD_SEC;
            if (!cert_expired) {
                /* Cert is still valid; RADIUS must have been a transient
                 * failure.  Return OK -- caller will retry enterprise. */
                ESP_LOGI(TAG,
                         "[smart] cert valid for %lld more s -- RADIUS transient?",
                         (long long)(expiry - now));
                heap_caps_free(creds);
                return ESP_OK;
            }
            ESP_LOGW(TAG,
                     "[smart] cert expires in %lld s -- renewing via SCEP",
                     (long long)(expiry - now));
        } else {
            /* Clock not synced -- can't evaluate expiry; re-enroll to be safe. */
            ESP_LOGW(TAG, "[smart] clock unsynced -- re-enrolling as precaution");
        }
    } else {
        ESP_LOGI(TAG, "[smart] no stored cert -- running SCEP enrollment");
    }
    heap_caps_free(creds);
#endif /* !SCEP_NO_NTP_USE_ISSUANCE_TIME */

    /* Run SCEP enrollment. */
#if defined(SCEP_URL) && defined(SCEP_CHALLENGE_PASSWORD)
    ESP_LOGI(TAG, "[smart] starting SCEP enrollment at %s", SCEP_URL);
    esp_err_t enroll_err = scep_enroll(SCEP_URL, SCEP_CHALLENGE_PASSWORD, NULL);
    if (enroll_err != ESP_OK) {
        ESP_LOGE(TAG, "[smart] SCEP enrollment failed: %s",
                 esp_err_to_name(enroll_err));
        return ESP_FAIL;
    }

#ifdef SCEP_NO_NTP_USE_ISSUANCE_TIME
    /* No-NTP mode: set the local clock from the issued cert's NotBefore.
     * This gives an approximately-correct wall-clock anchor (CA-attested "now")
     * so subsequent time(NULL) calls are in the right era for EAP-TLS. */
    {
        cred_store_t *fresh_creds = heap_caps_calloc(1, sizeof(cred_store_t),
                                                     MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
        if (fresh_creds && cred_store_load(fresh_creds) == ESP_OK && fresh_creds->dev_cert_len > 0) {
            uint64_t not_before_epoch = 0;
            esp_err_t nb_err = cred_store_parse_not_before(
                fresh_creds->dev_cert, fresh_creds->dev_cert_len,
                &not_before_epoch);
            if (nb_err == ESP_OK) {
                struct timeval tv = {
                    .tv_sec  = (time_t)not_before_epoch,
                    .tv_usec = 0,
                };
                settimeofday(&tv, NULL);
                ESP_LOGI(TAG,
                         "[smart] no-NTP mode: local time set to cert NotBefore"
                         " = %llu", (unsigned long long)not_before_epoch);
            } else {
                ESP_LOGW(TAG,
                         "[smart] no-NTP mode: cred_store_parse_not_before "
                         "failed (%s) -- clock unchanged",
                         esp_err_to_name(nb_err));
            }
        } else {
            ESP_LOGW(TAG,
                     "[smart] no-NTP mode: could not reload creds after "
                     "enrollment -- clock unchanged");
        }
        heap_caps_free(fresh_creds);
    }
#endif /* SCEP_NO_NTP_USE_ISSUANCE_TIME */

    ESP_LOGI(TAG, "[smart] SCEP enrollment succeeded -- rebooting for clean state");
    /* Reboot so the new cert is loaded from a clean state. */
    esp_restart();
    /* Not reached. */
#else
    ESP_LOGW(TAG, "[smart] SCEP_URL / SCEP_CHALLENGE_PASSWORD not defined -- "
                  "skipping enrollment; returning OK to retry enterprise");
#endif
    return ESP_OK;
}
#endif /* !WIFI_USE_ENTERPRISE -- end of smart_on_ip_full (Mode C only) */

/* Push CA cert and device cert+key from creds into the EAP supplicant.
 *
 * Used by both smart_configure_eaptls (NVS path) and smart_eap_apply_creds
 * (cert renewal path).  Does NOT call esp_wifi_sta_enterprise_enable() --
 * only smart_configure_eaptls does that so cert_renewer can update
 * credentials on a live connection without toggling the supplicant. */
static esp_err_t eap_push_nvs_creds(const cred_store_t *creds)
{
    esp_err_t err = esp_eap_client_set_ca_cert(
        creds->ca_chain, creds->ca_chain_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "[smart] set_ca_cert failed: %s",
                 esp_err_to_name(err));
        return ESP_FAIL;
    }

    err = esp_eap_client_set_certificate_and_key(
        creds->dev_cert, creds->dev_cert_len,
        creds->dev_key,  creds->dev_key_len,
        NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "[smart] set_certificate_and_key failed: %s",
                 esp_err_to_name(err));
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* Configure and start EAP-TLS.
 *
 * Feeds creds from NVS into the EAP supplicant if available; otherwise falls
 * back to the EMBED_TXTFILES compile-time certificates (if compiled in).
 * Returns ESP_OK if configuration was applied, ESP_FAIL on any setup error. */
static esp_err_t smart_configure_eaptls(const cred_store_t *creds)
{
    ESP_LOGI(TAG, "[smart] configuring EAP-TLS (identity: %s)", EAP_IDENTITY);

    ESP_ERROR_CHECK(esp_eap_client_set_identity(
        (const unsigned char *)EAP_IDENTITY, strlen(EAP_IDENTITY)));

    if (creds && creds->ca_chain_len > 0 && creds->dev_cert_len > 0 &&
        creds->dev_key_len > 0) {
        /* Use NVS-stored credentials. */
        ESP_LOGI(TAG, "[smart] using NVS creds (CA %u B, cert %u B, key %u B)",
                 (unsigned)creds->ca_chain_len,
                 (unsigned)creds->dev_cert_len,
                 (unsigned)creds->dev_key_len);

        esp_err_t err = eap_push_nvs_creds(creds);
        if (err != ESP_OK) {
            return err;
        }
    } else {
        /* Fallback: compile-time embedded certs (EMBED_TXTFILES path).
         * Only valid when WIFI_USE_ENTERPRISE was defined at build time. */
#ifdef WIFI_USE_ENTERPRISE
        ESP_LOGW(TAG, "[smart] NVS creds empty -- falling back to embedded certs");
        extern const uint8_t eap_ca_pem_start[]     asm("_binary_ca_pem_start");
        extern const uint8_t eap_ca_pem_end[]       asm("_binary_ca_pem_end");
        extern const uint8_t eap_client_crt_start[] asm("_binary_client_crt_start");
        extern const uint8_t eap_client_crt_end[]   asm("_binary_client_crt_end");
        extern const uint8_t eap_client_key_start[] asm("_binary_client_key_start");
        extern const uint8_t eap_client_key_end[]   asm("_binary_client_key_end");

        ESP_ERROR_CHECK(esp_eap_client_set_ca_cert(
            eap_ca_pem_start,
            eap_ca_pem_end - eap_ca_pem_start));
        ESP_ERROR_CHECK(esp_eap_client_set_certificate_and_key(
            eap_client_crt_start,
            eap_client_crt_end - eap_client_crt_start,
            eap_client_key_start,
            eap_client_key_end - eap_client_key_start,
            NULL, 0));
#else
        ESP_LOGE(TAG, "[smart] no NVS creds and no embedded certs -- "
                      "EAP-TLS will fail");
        return ESP_FAIL;
#endif
    }

    /* EAP-TLS only: with just cert+key configured the IDF supplicant
     * auto-selects EAP-TLS (no method-restriction API in IDF 5.4.1). */
    ESP_ERROR_CHECK(esp_wifi_sta_enterprise_enable());
    return ESP_OK;
}

/* Push new EAP-TLS credentials into the supplicant while already connected.
 *
 * Called by cert_renewer.c after a successful SCEP re-enrollment.
 * Only available for Mode C (WIFI_ENTERPRISE_SSID without WIFI_USE_ENTERPRISE).
 * Mode B+ uses embedded certs and has no cert renewer. */
#ifndef WIFI_USE_ENTERPRISE
esp_err_t smart_eap_apply_creds(const cred_store_t *creds)
{
    if (!creds || creds->ca_chain_len == 0 ||
        creds->dev_cert_len == 0 || creds->dev_key_len == 0) {
        ESP_LOGE(TAG, "[smart] smart_eap_apply_creds: credentials are empty");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "[smart] applying renewed EAP-TLS creds "
                  "(CA %u B, cert %u B, key %u B)",
             (unsigned)creds->ca_chain_len,
             (unsigned)creds->dev_cert_len,
             (unsigned)creds->dev_key_len);

    return eap_push_nvs_creds(creds);
}
#endif /* !WIFI_USE_ENTERPRISE -- end of smart_eap_apply_creds (Mode C only) */

/* Bring up the enterprise (EAP-TLS) network, wait up to timeout_sec for an IP.
 *
 * Returns ESP_OK if IP obtained, ESP_FAIL if timeout or disconnect. */
static esp_err_t wifi_mode_enterprise(const char         *ssid,
                                       uint32_t            timeout_sec,
                                       const cred_store_t *creds)
{
    ESP_LOGI(TAG, "[smart] connecting to enterprise network \"%s\" "
                  "(timeout %u s)", ssid, (unsigned)timeout_sec);

    wifi_config_t cfg = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_ENTERPRISE,
            .pmf_cfg = {
                .capable  = true,
                .required = true,
            },
        },
    };
    strncpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);

    /* Configure EAP-TLS credentials. */
    if (smart_configure_eaptls(creds) != ESP_OK) {
        return ESP_FAIL;
    }

    xEventGroupClearBits(s_wifi_event_group,
                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    s_retry_num = 0;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    TickType_t wait = (timeout_sec == 0)
        ? portMAX_DELAY
        : pdMS_TO_TICKS(timeout_sec * 1000u);

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        wait);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "[smart] enterprise connected to \"%s\"", ssid);
        return ESP_OK;
    }

    ESP_LOGE(TAG, "[smart] enterprise connect to \"%s\" failed/timed out", ssid);
    esp_wifi_stop();
    esp_wifi_sta_enterprise_disable();
    return ESP_FAIL;
}

/* --------------------------------------------------------------------------
 * Public entry points
 * -------------------------------------------------------------------------- */

/* wifi_smart_init_common -- shared preamble for wifi_init_smart (Mode C) and
 * wifi_init_enterprise_bootstrap (Mode B+).
 *
 * Creates the event group, DHCP watchdog, TCP/IP stack, netif, WiFi driver,
 * and persistent event handler registrations that both entry points need.
 * Writes the two handler instance handles to *out_inst_wifi / *out_inst_ip
 * so callers can unregister them once the enterprise connection is established.
 *
 * Returns ESP_OK on success; aborts via configASSERT / ESP_ERROR_CHECK on any
 * unrecoverable setup failure (same behaviour as the original per-function
 * code). */
static esp_err_t wifi_smart_init_common(
    esp_event_handler_instance_t *out_inst_wifi,
    esp_event_handler_instance_t *out_inst_ip)
{
    /* 1. Shared resources (event group, DHCP watchdog). */
    s_wifi_event_group = xEventGroupCreate();
    configASSERT(s_wifi_event_group);

#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
    s_dhcp_watchdog = xTimerCreate(
        "dhcp_wd",
        pdMS_TO_TICKS(DHCP_RETRY_TIMEOUT_SEC * 1000),
        pdFALSE, NULL, dhcp_watchdog_cb);
    if (!s_dhcp_watchdog) {
        ESP_LOGW(TAG, "[smart] DHCP watchdog timer creation failed");
    }
#endif

    /* 2. TCP/IP stack + netif. */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_sta_netif = esp_netif_create_default_wifi_sta();
    configASSERT(s_sta_netif);

    esp_err_t herr = esp_netif_set_hostname(s_sta_netif, DEVICE_HOSTNAME);
    if (herr != ESP_OK) {
        ESP_LOGW(TAG, "[smart] set_hostname failed: %s",
                 esp_err_to_name(herr));
    }

    /* 3. WiFi driver init (once). */
    wifi_init_config_t driver_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&driver_cfg));

    /* 4. Persistent event handlers (reconnect + IP logging). */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID,
        &wifi_event_handler, NULL, out_inst_wifi));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP,
        &wifi_event_handler, NULL, out_inst_ip));

#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
    esp_event_handler_instance_t inst_ip6;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_GOT_IP6,
        &wifi_event_handler, NULL, &inst_ip6));
    (void)inst_ip6;
#endif

    return ESP_OK;
}

/* wifi_init_smart -- Mode C (SCEP/NVS, no embedded enterprise certs) */
#ifndef WIFI_USE_ENTERPRISE
esp_err_t wifi_init_smart(void)
{
    esp_event_handler_instance_t inst_wifi;
    esp_event_handler_instance_t inst_ip;
    wifi_smart_init_common(&inst_wifi, &inst_ip);

    /* 5. Load stored credentials.
     *
     * cred_store_t is ~14 KB (dev_key[2048] + dev_cert[4096] + ca_chain[8192]
     * + metadata).  The main task's stack is only 3584 bytes, so declaring
     * this on the stack would smash the heap immediately below it.  Allocate
     * on the heap instead.  We use internal RAM (not PSRAM) to ensure the
     * buffers are accessible from any context (NVS, mbedTLS, EAP supplicant). */
    cred_store_t *creds_p = heap_caps_calloc(1, sizeof(cred_store_t),
                                              MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    if (!creds_p) {
        ESP_LOGE(TAG, "[smart] failed to allocate cred_store_t (%u B) -- aborting",
                 (unsigned)sizeof(cred_store_t));
        return ESP_ERR_NO_MEM;
    }
    bool cert_present = (cred_store_load(creds_p) == ESP_OK);

    /* 6. Evaluate initial clock. */
    time_t now = time(NULL);
    bool ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);

    /* 7. Cert expiry check (only when cert exists and clock is plausible). */
    bool cert_expired = false;
    if (cert_present && ntp_synced) {
        time_t expiry = (time_t)creds_p->not_after;
        cert_expired = (expiry - now) < (time_t)CERT_REENROLL_THRESHOLD_SEC;
        if (cert_expired) {
            ESP_LOGW(TAG, "[smart] cert expires in %lld s -- will re-enroll",
                     (long long)(expiry - now));
        } else {
            ESP_LOGI(TAG, "[smart] cert valid for %lld more s",
                     (long long)(expiry - now));
        }
    }

    bool ntp_req = (NTP_BEFORE_EAPTLS != 0);

#ifdef SCEP_NO_NTP_USE_ISSUANCE_TIME
    bool no_ntp = true;
#else
    bool no_ntp = false;
#endif

    int enterprise_attempts = 0;

    /* 8. Main loop -- iterate until enterprise is up or all paths fail. */
    for (;;) {
        wifi_decision_t decision = wifi_decide_next_step(
            cert_present, cert_expired, ntp_synced,
            ntp_req, no_ntp, enterprise_attempts, WIFI_ENTERPRISE_RETRY_MAX);

        ESP_LOGI(TAG, "[smart] decision=%d (cert=%d expired=%d synced=%d "
                      "ntp_req=%d attempts=%d max=%d)",
                 (int)decision, (int)cert_present, (int)cert_expired,
                 (int)ntp_synced, (int)ntp_req,
                 enterprise_attempts, WIFI_ENTERPRISE_RETRY_MAX);

        if (decision == WIFI_DECISION_ENTERPRISE) {
            enterprise_attempts++;
            esp_err_t rc = wifi_mode_enterprise(
                WIFI_ENTERPRISE_SSID,
                (uint32_t)EAPTLS_HANDSHAKE_TIMEOUT_SEC,
                cert_present ? creds_p : NULL);

            if (rc == ESP_OK) {
                /* DONE: enterprise is connected.
                 * Deregister the bootstrap event instances; the persistent
                 * wifi_event_handler keeps running for reconnect. */
                esp_event_handler_instance_unregister(
                    IP_EVENT, IP_EVENT_STA_GOT_IP, inst_ip);
                esp_event_handler_instance_unregister(
                    WIFI_EVENT, ESP_EVENT_ANY_ID, inst_wifi);

#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
                mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
                ntp_dispatch_start();
#endif
                heap_caps_free(creds_p);
                return ESP_OK;
            }

            /* Enterprise failed.  Loop back to wifi_decide_next_step with
             * the updated attempt count; it will decide what to do. */
            ESP_LOGW(TAG,
                     "[smart] enterprise attempt %d failed -- re-evaluating",
                     enterprise_attempts);
            continue;

        } else if (decision == WIFI_DECISION_BOOTSTRAP_NTP_ONLY) {
            ESP_LOGI(TAG, "[smart] bootstrap NTP-only pass on \"%s\"",
                     WIFI_SSID);
            esp_err_t rc = wifi_mode_psk(WIFI_SSID, WIFI_PASS,
                                          smart_on_ip_ntp_only);
            if (rc != ESP_OK) {
                ESP_LOGW(TAG, "[smart] bootstrap PSK connect failed");
            }
            /* Refresh NTP state for next decision. */
            now = time(NULL);
            ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);
            /* Loop -- next decision should now be ENTERPRISE (or FULL if
             * something went wrong). */
            continue;

        } else { /* WIFI_DECISION_BOOTSTRAP_FULL */
            ESP_LOGI(TAG, "[smart] bootstrap full pass on \"%s\"", WIFI_SSID);
            esp_err_t rc = wifi_mode_psk(WIFI_SSID, WIFI_PASS,
                                          smart_on_ip_full);
            /* smart_on_ip_full calls esp_restart() on successful enrollment;
             * reaching here means either:
             *   a) SCEP succeeded but esp_restart hasn't fired yet (impossible
             *      with esp_restart in the callback), or
             *   b) no SCEP_URL defined (fallback warning was logged), or
             *   c) enrollment failed.
             *
             * In case (b) the cert is still valid (transient RADIUS failure).
             * Re-evaluate with updated state so we retry enterprise. */
            if (rc != ESP_OK) {
                ESP_LOGE(TAG,
                         "[smart] bootstrap full pass failed (PSK or SCEP) -- "
                         "retrying enterprise anyway");
                /* Reload creds in case partial enrollment wrote something. */
                cert_present = (cred_store_load(creds_p) == ESP_OK);
            }
            now = time(NULL);
            ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);
            /* Re-check expiry now that time may be synced. */
            if (cert_present && ntp_synced) {
                time_t expiry = (time_t)creds_p->not_after;
                cert_expired = (expiry - now) < (time_t)CERT_REENROLL_THRESHOLD_SEC;
            } else {
                cert_expired = false;
            }
            /* Reset enterprise attempt counter so the retry budget is fresh. */
            enterprise_attempts = 0;
            continue;
        }
    }

    /* Unreachable -- loop only exits via return ESP_OK or esp_restart(). */
    heap_caps_free(creds_p);
    return ESP_FAIL;
}
#endif /* !WIFI_USE_ENTERPRISE -- end of wifi_init_smart (Mode C only) */

/* --------------------------------------------------------------------------
 * wifi_init_enterprise_bootstrap -- Mode B+ (embedded certs + PSK bootstrap)
 *
 * Available only when BOTH WIFI_USE_ENTERPRISE and WIFI_ENTERPRISE_SSID are
 * defined.  Like Mode C's wifi_init_smart() but without SCEP or cred_store:
 *   - Build-embedded ca.pem / client.crt / client.key are always used.
 *   - WIFI_SSID / WIFI_PASS is the PSK bootstrap network used only for NTP.
 *   - WIFI_ENTERPRISE_SSID is the EAP-TLS production network.
 *   - The decision function only ever returns BOOTSTRAP_NTP_ONLY or ENTERPRISE
 *     (cert_present=true, cert_expired=false always -- embedded certs are
 *     static).  BOOTSTRAP_FULL cannot happen because cert_present is always
 *     true and the retry-budget-exhausted path would be a runaway loop; to
 *     guard against it we just proceed to ENTERPRISE on that branch too.
 * -------------------------------------------------------------------------- */
#ifdef WIFI_USE_ENTERPRISE
esp_err_t wifi_init_enterprise_bootstrap(void)
{
    esp_event_handler_instance_t inst_wifi;
    esp_event_handler_instance_t inst_ip;
    wifi_smart_init_common(&inst_wifi, &inst_ip);

    /* 5. Embedded certs sanity-check.  Cert is always "present" and treated as
     *    non-expired (we cannot evaluate NotAfter without a synced clock and
     *    without parsing the cert -- NTP bootstrap is the mechanism for that). */
    configASSERT((eap_ca_pem_end  - eap_ca_pem_start)        >= EAP_CA_MIN_BYTES);
    configASSERT((eap_client_crt_end - eap_client_crt_start)  >= EAP_CRT_MIN_BYTES);
    configASSERT((eap_client_key_end - eap_client_key_start)  >= EAP_KEY_MIN_BYTES);

    const bool cert_present  = true;
    const bool cert_expired  = false;

    /* 6. Evaluate clock. */
    time_t now = time(NULL);
    bool ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);

    bool ntp_req = (NTP_BEFORE_EAPTLS != 0);

    int enterprise_attempts = 0;

    /* 7. Main loop. */
    for (;;) {
        wifi_decision_t decision = wifi_decide_next_step(
            cert_present, cert_expired, ntp_synced,
            ntp_req, false /* no_ntp_mode */,
            enterprise_attempts, WIFI_ENTERPRISE_RETRY_MAX);

        ESP_LOGI(TAG, "[b+] decision=%d (synced=%d ntp_req=%d attempts=%d max=%d)",
                 (int)decision, (int)ntp_synced, (int)ntp_req,
                 enterprise_attempts, WIFI_ENTERPRISE_RETRY_MAX);

        if (decision == WIFI_DECISION_ENTERPRISE ||
            decision == WIFI_DECISION_BOOTSTRAP_FULL) {
            /* BOOTSTRAP_FULL cannot normally happen for Mode B+ (cert_present is
             * always true and cert_expired is always false).  The only way to
             * reach it is if the enterprise retry budget is exhausted, which
             * means the RADIUS server is persistently refusing the cert.  Log a
             * warning and attempt enterprise anyway rather than looping forever. */
            if (decision == WIFI_DECISION_BOOTSTRAP_FULL) {
                ESP_LOGW(TAG, "[b+] enterprise retry budget exhausted -- "
                              "proceeding to enterprise (cert is embedded, "
                              "no re-enrollment available for Mode B+)");
            }
            enterprise_attempts++;
            esp_err_t rc = wifi_mode_enterprise(
                WIFI_ENTERPRISE_SSID,
                (uint32_t)EAPTLS_HANDSHAKE_TIMEOUT_SEC,
                NULL /* creds -- always use embedded path */);

            if (rc == ESP_OK) {
                esp_event_handler_instance_unregister(
                    IP_EVENT, IP_EVENT_STA_GOT_IP, inst_ip);
                esp_event_handler_instance_unregister(
                    WIFI_EVENT, ESP_EVENT_ANY_ID, inst_wifi);
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
                mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
                ntp_dispatch_start();
#endif
                return ESP_OK;
            }

            ESP_LOGW(TAG, "[b+] enterprise attempt %d failed -- re-evaluating",
                     enterprise_attempts);
            continue;

        } else { /* WIFI_DECISION_BOOTSTRAP_NTP_ONLY */
            ESP_LOGI(TAG, "[b+] bootstrap NTP-only pass on \"%s\"", WIFI_SSID);
            esp_err_t rc = wifi_mode_psk(WIFI_SSID, WIFI_PASS,
                                          smart_on_ip_ntp_only);
            if (rc != ESP_OK) {
                ESP_LOGW(TAG, "[b+] bootstrap PSK connect failed");
            }
            now = time(NULL);
            ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);
            continue;
        }
    }

    /* Unreachable. */
    return ESP_FAIL;
}
#endif /* WIFI_USE_ENTERPRISE -- end of wifi_init_enterprise_bootstrap (Mode B+) */

#endif /* WIFI_ENTERPRISE_SSID */
