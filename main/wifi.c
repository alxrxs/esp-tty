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

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/timers.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_wifi.h"

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

#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
#include "mdns.h"
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

static volatile bool s_mdns_started = false;

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

static void mdns_dispatch_start(void)
{
    if (s_mdns_started) return;
    s_mdns_started = true;

    BaseType_t ret = xTaskCreate(mdns_start_task, "mdns_start",
                                 4096, NULL,
                                 tskIDLE_PRIORITY + 1, NULL);
    if (ret != pdPASS) {
        ESP_LOGW(TAG, "xTaskCreate(mdns_start_task) failed -- mDNS not started");
        s_mdns_started = false;   /* allow a retry on next connect */
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
            /* Driver is up -- kick off the first connection attempt. */
            ESP_LOGI(TAG, "STA started, connecting to \"%s\" ...", WIFI_SSID);
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

    /* Restrict to EAP-TLS only so the supplicant doesn't fall back to
     * PEAP/TTLS if the server offers them (belt-and-suspenders). */
    ESP_ERROR_CHECK(esp_eap_client_set_eap_methods(ESP_EAP_TYPE_TLS));

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
