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
 *     Static IPv4 for the enterprise/production network -- DHCP client is
 *     stopped before the interface comes up.  Requires STATIC_IPV4_ADDRESS,
 *     STATIC_IPV4_NETMASK, STATIC_IPV4_GATEWAY (all dotted-decimal strings).
 *     Optional: STATIC_IPV4_DNS_PRIMARY, STATIC_IPV4_DNS_SECONDARY.  The
 *     DHCP watchdog is disabled automatically.
 *
 *     PSK bootstrap network (Mode B+/C): when USE_STATIC_IPV4 is defined but
 *     USE_STATIC_IPV4_BOOTSTRAP is not, the bootstrap network (WIFI_SSID)
 *     always uses DHCP -- the bootstrap subnet may differ from the production
 *     subnet and is only used for NTP sync / SCEP enrollment.
 *
 *   With USE_STATIC_IPV4_BOOTSTRAP defined (requires WIFI_ENTERPRISE_SSID):
 *     Static IPv4 for the PSK bootstrap network as well.  Requires
 *     BOOTSTRAP_STATIC_IPV4_ADDRESS, BOOTSTRAP_STATIC_IPV4_NETMASK,
 *     BOOTSTRAP_STATIC_IPV4_GATEWAY.  Optional: BOOTSTRAP_STATIC_IPV4_DNS_PRIMARY,
 *     BOOTSTRAP_STATIC_IPV4_DNS_SECONDARY.
 *
 * IPv6 addressing (selected in config.h via IPV6_MODE / BOOTSTRAP_IPV6_MODE):
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
 *   BOOTSTRAP_IPV6_MODE selects the IPv6 mode for the PSK bootstrap network
 *   when USE_STATIC_IPV4_BOOTSTRAP is defined.  Defaults to IPV6_MODE_DISABLED
 *   when not set (static IPv6 addressing belongs to the enterprise interface,
 *   not the transient bootstrap VLAN).  When set to IPV6_MODE_STATIC, requires
 *   BOOTSTRAP_STATIC_IPV6_ADDRESS, BOOTSTRAP_STATIC_IPV6_PREFIX_LEN,
 *   BOOTSTRAP_STATIC_IPV6_GATEWAY.  Optional: BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY,
 *   BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY.
 *
 * Compile-time credentials come from main/config.h (gitignored).
 * Copy config.h.example -> config.h and fill in your values.
 */

#include <stdatomic.h>
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
#include "esp_random.h"

/* config.h must come before the WIFI_USE_ENTERPRISE guard below because
 * that macro is defined there (not on the command line). */
#include "wifi.h"
#include "wifi_backoff.h"
#ifdef BRIDGE_LOOPBACK
/* QEMU/Wokwi simulation: open AP, no password, no authmode requirement */
#define WIFI_SSID  "Wokwi-GUEST"
#define WIFI_PASS  ""
#define WIFI_AUTH_THRESHOLD  WIFI_AUTH_OPEN
#define WIFI_SAE_MODE        WPA3_SAE_PWE_UNSPECIFIED
#else
#include "config.h"   /* WIFI_SSID, WIFI_PASS, and optionally EAP_IDENTITY */
#endif

/* UDP log mirror -- included after config.h so UDP_LOG_HOST / UDP_LOG_PORT
 * are visible.  The header provides no-op stubs when the macros are absent. */
#include "udp_log.h"

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

/* Fallback floor used by SCEP_NO_NTP_USE_ISSUANCE_TIME mode before the
 * first enrollment.  Override in config.h to a more recent epoch if the
 * firmware lives long without a re-flash.  Defaults to 2025-01-01 UTC,
 * which is recent enough to reject pre-issued certs but old enough to
 * accept any cert minted for this firmware.  See M15. */
#if defined(SCEP_NO_NTP_USE_ISSUANCE_TIME) && !defined(SCEP_NO_NTP_BUILD_EPOCH)
#  define SCEP_NO_NTP_BUILD_EPOCH 1735689600  /* 2025-01-01T00:00:00Z */
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

#include "mbedtls/x509_crt.h"

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

/* Bootstrap static IPv4/IPv6 is only meaningful in smart mode (WIFI_ENTERPRISE_SSID). */
#if defined(USE_STATIC_IPV4_BOOTSTRAP) && !defined(WIFI_ENTERPRISE_SSID)
# error "USE_STATIC_IPV4_BOOTSTRAP requires WIFI_ENTERPRISE_SSID (Mode B+ or C)"
#endif

#ifdef USE_STATIC_IPV4_BOOTSTRAP
# ifndef BOOTSTRAP_STATIC_IPV4_ADDRESS
#  error "USE_STATIC_IPV4_BOOTSTRAP requires BOOTSTRAP_STATIC_IPV4_ADDRESS in config.h"
# endif
# ifndef BOOTSTRAP_STATIC_IPV4_NETMASK
#  error "USE_STATIC_IPV4_BOOTSTRAP requires BOOTSTRAP_STATIC_IPV4_NETMASK in config.h"
# endif
# ifndef BOOTSTRAP_STATIC_IPV4_GATEWAY
#  error "USE_STATIC_IPV4_BOOTSTRAP requires BOOTSTRAP_STATIC_IPV4_GATEWAY in config.h"
# endif
/* Default bootstrap IPv6 mode to DISABLED when the user has not specified one. */
# ifndef BOOTSTRAP_IPV6_MODE
#  define BOOTSTRAP_IPV6_MODE  IPV6_MODE_DISABLED
# endif
# if BOOTSTRAP_IPV6_MODE == IPV6_MODE_STATIC
#  ifndef BOOTSTRAP_STATIC_IPV6_ADDRESS
#   error "BOOTSTRAP_IPV6_MODE==IPV6_MODE_STATIC requires BOOTSTRAP_STATIC_IPV6_ADDRESS in config.h"
#  endif
#  ifndef BOOTSTRAP_STATIC_IPV6_PREFIX_LEN
#   error "BOOTSTRAP_IPV6_MODE==IPV6_MODE_STATIC requires BOOTSTRAP_STATIC_IPV6_PREFIX_LEN in config.h"
#  endif
#  ifndef BOOTSTRAP_STATIC_IPV6_GATEWAY
#   error "BOOTSTRAP_IPV6_MODE==IPV6_MODE_STATIC requires BOOTSTRAP_STATIC_IPV6_GATEWAY in config.h"
#  endif
# endif /* BOOTSTRAP_IPV6_MODE == IPV6_MODE_STATIC */
#endif /* USE_STATIC_IPV4_BOOTSTRAP */

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
/* s_retry_num is read/written by both the system event-loop task (in the
 * disconnect handler) and the application task that observes connection
 * progress.  On dual-core ESP32-S3 plain `int` provides no cross-core
 * visibility; use _Atomic with default seq_cst ordering. */
static _Atomic int        s_retry_num = 0;

/* Double-init guard: esp_netif_init / esp_event_loop_create_default /
 * esp_wifi_init must each be called exactly once.  Without this flag,
 * a second call into wifi_smart_init_common / wifi_init_sta /
 * wifi_init_smart / wifi_init_enterprise_bootstrap would abort via
 * ESP_ERROR_CHECK on ESP_ERR_INVALID_STATE. */
static _Atomic bool s_wifi_inited = false;

/* Safely (re)create the WiFi event group, freeing any existing handle
 * so a stale handle isn't leaked across re-init paths. */
static void wifi_event_group_reset(void) {
    if (s_wifi_event_group != NULL) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = NULL;
    }
    s_wifi_event_group = xEventGroupCreate();
    configASSERT(s_wifi_event_group);
}

/* Kept so the enterprise extension point can call esp_netif_get_ip_info()
 * from a task if needed. */
static esp_netif_t *s_sta_netif = NULL;

/* PSK bootstrap active flag (Mode B+ / C only).
 *
 * Set true in wifi_mode_psk() before esp_wifi_start() and cleared false in
 * wifi_mode_enterprise() before esp_wifi_start().  The WIFI_EVENT_STA_CONNECTED
 * handler uses this to choose between DHCP and static IPv4 when USE_STATIC_IPV4
 * is defined: the bootstrap PSK network is transient (seconds) and may reside
 * on a different subnet from the production enterprise network, so it always
 * uses DHCP regardless of the USE_STATIC_IPV4 setting.  Static addressing
 * applies only after the enterprise SSID is joined.
 *
 * Only compiled when WIFI_ENTERPRISE_SSID is defined (smart mode only); in
 * Mode A/B this flag is unused and the compiler removes it entirely. */
#ifdef WIFI_ENTERPRISE_SSID
static bool s_psk_bootstrap_active = false;
#endif

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
 * Static IPv4 configuration helpers
 *
 * apply_static_ipv4_core() does the actual work: stop DHCP, set address,
 * optionally configure DNS servers.  dns_pri and dns_sec may be NULL.
 *
 * apply_static_ipv4_enterprise() and apply_static_ipv4_bootstrap() are thin
 * wrappers that pass the right compile-time macro strings.
 * -------------------------------------------------------------------------- */
#if defined(USE_STATIC_IPV4) || defined(USE_STATIC_IPV4_BOOTSTRAP)
static void apply_static_ipv4_core(const char *addr,
                                   const char *netmask,
                                   const char *gw,
                                   const char *dns_pri,
                                   const char *dns_sec)
{
    esp_netif_ip_info_t ip_info = {};

    if (esp_netif_str_to_ip4(addr, &ip_info.ip) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid static IPv4 address: \"%s\"", addr);
        return;
    }
    if (esp_netif_str_to_ip4(netmask, &ip_info.netmask) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid static IPv4 netmask: \"%s\"", netmask);
        return;
    }
    if (esp_netif_str_to_ip4(gw, &ip_info.gw) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid static IPv4 gateway: \"%s\"", gw);
        return;
    }

    /* Stop the DHCP client before setting a static address.  It may not be
     * running yet (INIT state), but the call is harmless in that case. */
    esp_err_t err = esp_netif_dhcpc_stop(s_sta_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGW(TAG, "esp_netif_dhcpc_stop: %s", esp_err_to_name(err));
    }

    err = esp_netif_set_ip_info(s_sta_netif, &ip_info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_set_ip_info failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "Static IPv4: " IPSTR " / " IPSTR " gw " IPSTR,
             IP2STR(&ip_info.ip),
             IP2STR(&ip_info.netmask),
             IP2STR(&ip_info.gw));

    /* Optional static DNS servers. */
    if (dns_pri) {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        if (esp_netif_str_to_ip4(dns_pri, &dns.ip.u_addr.ip4) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "Static DNS primary: %s", dns_pri);
        } else {
            ESP_LOGW(TAG, "Invalid static DNS primary: \"%s\"", dns_pri);
        }
    }

    if (dns_sec) {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        if (esp_netif_str_to_ip4(dns_sec, &dns.ip.u_addr.ip4) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_BACKUP, &dns);
            ESP_LOGI(TAG, "Static DNS secondary: %s", dns_sec);
        } else {
            ESP_LOGW(TAG, "Invalid static DNS secondary: \"%s\"", dns_sec);
        }
    }
}
#endif /* USE_STATIC_IPV4 || USE_STATIC_IPV4_BOOTSTRAP */

#ifdef USE_STATIC_IPV4
static void apply_static_ipv4_enterprise(void)
{
    apply_static_ipv4_core(
        STATIC_IPV4_ADDRESS,
        STATIC_IPV4_NETMASK,
        STATIC_IPV4_GATEWAY,
#ifdef STATIC_IPV4_DNS_PRIMARY
        STATIC_IPV4_DNS_PRIMARY,
#else
        NULL,
#endif
#ifdef STATIC_IPV4_DNS_SECONDARY
        STATIC_IPV4_DNS_SECONDARY
#else
        NULL
#endif
    );
}
#endif /* USE_STATIC_IPV4 */

#ifdef USE_STATIC_IPV4_BOOTSTRAP
static void apply_static_ipv4_bootstrap(void)
{
    apply_static_ipv4_core(
        BOOTSTRAP_STATIC_IPV4_ADDRESS,
        BOOTSTRAP_STATIC_IPV4_NETMASK,
        BOOTSTRAP_STATIC_IPV4_GATEWAY,
#ifdef BOOTSTRAP_STATIC_IPV4_DNS_PRIMARY
        BOOTSTRAP_STATIC_IPV4_DNS_PRIMARY,
#else
        NULL,
#endif
#ifdef BOOTSTRAP_STATIC_IPV4_DNS_SECONDARY
        BOOTSTRAP_STATIC_IPV4_DNS_SECONDARY
#else
        NULL
#endif
    );
}
#endif /* USE_STATIC_IPV4_BOOTSTRAP */

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
 * Bootstrap IPv6 bring-up helper
 *
 * Used only when USE_STATIC_IPV4_BOOTSTRAP is defined.  Applies
 * BOOTSTRAP_IPV6_MODE (defaults to IPV6_MODE_DISABLED) on the PSK bootstrap
 * interface instead of leaking the enterprise IPv6 config onto a different
 * VLAN.
 * -------------------------------------------------------------------------- */
#if defined(USE_STATIC_IPV4_BOOTSTRAP) && \
    defined(CONFIG_LWIP_IPV6) && \
    BOOTSTRAP_IPV6_MODE != IPV6_MODE_DISABLED
static void ipv6_bring_up_bootstrap(void)
{
    /* Create a link-local address (fe80::) for all non-disabled IPv6 modes. */
    esp_err_t err = esp_netif_create_ip6_linklocal(s_sta_netif);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ipv6_bring_up_bootstrap: create_ip6_linklocal: %s",
                 esp_err_to_name(err));
    }

# if BOOTSTRAP_IPV6_MODE == IPV6_MODE_STATIC
    /* Add the statically configured bootstrap global unicast address. */
    esp_ip6_addr_t addr6 = {};
    if (esp_netif_str_to_ip6(BOOTSTRAP_STATIC_IPV6_ADDRESS, &addr6) != ESP_OK) {
        ESP_LOGE(TAG, "Invalid BOOTSTRAP_STATIC_IPV6_ADDRESS: \"%s\"",
                 BOOTSTRAP_STATIC_IPV6_ADDRESS);
        return;
    }
    esp_err_t aerr = esp_netif_add_ip6_address(s_sta_netif, addr6, true);
    if (aerr != ESP_OK) {
        ESP_LOGW(TAG, "ipv6_bring_up_bootstrap: add_ip6_address: %s",
                 esp_err_to_name(aerr));
    } else {
        ESP_LOGI(TAG, "Bootstrap static IPv6: " IPV6STR "/%d",
                 IPV62STR(addr6), (int)BOOTSTRAP_STATIC_IPV6_PREFIX_LEN);
    }

#  ifdef BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY
    {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V6;
        if (esp_netif_str_to_ip6(BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY,
                                 &dns.ip.u_addr.ip6) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "Bootstrap static IPv6 DNS primary: %s",
                     BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY);
        } else {
            ESP_LOGW(TAG, "Invalid BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY: \"%s\"",
                     BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY);
        }
    }
#  endif /* BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY */

#  ifdef BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY
    {
        esp_netif_dns_info_t dns = {};
        dns.ip.type = ESP_IPADDR_TYPE_V6;
        if (esp_netif_str_to_ip6(BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY,
                                 &dns.ip.u_addr.ip6) == ESP_OK) {
            esp_netif_set_dns_info(s_sta_netif, ESP_NETIF_DNS_BACKUP, &dns);
            ESP_LOGI(TAG, "Bootstrap static IPv6 DNS secondary: %s",
                     BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY);
        } else {
            ESP_LOGW(TAG, "Invalid BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY: \"%s\"",
                     BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY);
        }
    }
#  endif /* BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY */
# endif /* BOOTSTRAP_IPV6_MODE == IPV6_MODE_STATIC */
}
#endif /* USE_STATIC_IPV4_BOOTSTRAP && CONFIG_LWIP_IPV6 && BOOTSTRAP_IPV6_MODE != DISABLED */

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

static _Atomic bool s_ntp_started = false;

/* Cert-renewal post-disconnect reconnect signal.
 *
 * Lifecycle (single-shot, edge-triggered):
 *   1. cert_renewer calls wifi_signal_eap_creds_rotated() exactly ONCE,
 *      then calls esp_wifi_disconnect().
 *   2. The NEXT WIFI_EVENT_STA_DISCONNECTED event (regardless of reason)
 *      consumes the flag via atomic_exchange and clears it.
 *      - If the reason is ASSOC_LEAVE (the expected outcome of our own
 *        disconnect call), the handler reconnects with the new creds.
 *      - If the reason is anything else (e.g. AUTH_FAIL because RADIUS
 *        rejected the new cert, or BEACON_TIMEOUT because the AP went
 *        away first), the handler still consumes the flag (so it cannot
 *        leak into a future unrelated ASSOC_LEAVE) and falls through to
 *        the normal classification + backoff path -- which is the right
 *        answer for those reasons.
 *
 * Only meaningfully set in Mode C builds where the cert_renewer task runs,
 * but the flag is defined unconditionally to keep the handler simple. */
static _Atomic bool s_eap_creds_just_rotated = false;

void wifi_signal_eap_creds_rotated(void)
{
    atomic_store(&s_eap_creds_just_rotated, true);
}

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
    if (n_servers > CONFIG_LWIP_SNTP_MAX_SERVERS) {
        for (size_t i = CONFIG_LWIP_SNTP_MAX_SERVERS; i < n_servers; i++) {
            ESP_LOGW(TAG, "NTP server[%u] \"%s\" dropped (exceeds "
                          "CONFIG_LWIP_SNTP_MAX_SERVERS=%d)",
                     (unsigned)i, servers[i], CONFIG_LWIP_SNTP_MAX_SERVERS);
        }
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

    /* Clear any prior SNTP singleton state so re-association events (which
     * re-enter this task path via the s_ntp_started guard being externally
     * reset, or via Wi-Fi-driver-internal SNTP touch) don't see "already
     * initialized" and bail out. */
    esp_netif_sntp_deinit();

    esp_err_t err = esp_netif_sntp_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_sntp_init failed: %s", esp_err_to_name(err));
        atomic_store(&s_ntp_started, false);
        vTaskDelete(NULL);
        return;
    }

    /* Apply timezone before waiting so any logged timestamps are local. */
    char tz_buf[NTP_TZ_MAX_LEN + 1];
    snprintf(tz_buf, sizeof(tz_buf), "%s", NTP_TIMEZONE);
    setenv("TZ", tz_buf, 1);
    tzset();

    ESP_LOGW(TAG, "NTP is unauthenticated (no NTS); an on-path attacker can "
                  "manipulate the clock");

    /* Wait up to NTP_SYNC_TIMEOUT_SEC; log progress, then background. */
    TickType_t ntp_start = xTaskGetTickCount();
    TickType_t ntp_timeout = pdMS_TO_TICKS((uint32_t)NTP_SYNC_TIMEOUT_SEC * 1000u);
    while ((xTaskGetTickCount() - ntp_start) < ntp_timeout) {
        esp_err_t wret = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(5000));
        if (wret == ESP_OK) {
            /* sync_cb already logged the timestamp.
             *
             * M1.B: clear s_ntp_started so that a subsequent WiFi reconnect
             * that calls ntp_dispatch_start() (via IP_EVENT_STA_GOT_IP) can
             * start a fresh NTP sync on the new netif.  Without this reset the
             * atomic_exchange guard in ntp_dispatch_start() would see "true"
             * forever after the first successful sync and permanently block
             * re-sync on WiFi reconnects. */
            atomic_store(&s_ntp_started, false);
            vTaskDelete(NULL);
            return;
        }
        ESP_LOGI(TAG, "NTP: waiting for sync ...");
    }
    ESP_LOGW(TAG, "NTP: sync not complete within %d s -- continuing in background",
             NTP_SYNC_TIMEOUT_SEC);

    /* M1.B: also clear the guard on the timeout path so that a subsequent
     * WiFi reconnect can re-attempt NTP sync.  The SNTP client continues
     * running in the background (esp_netif_sntp_deinit is not called here),
     * but ntp_dispatch_start() is allowed to start a fresh task next time. */
    atomic_store(&s_ntp_started, false);
    vTaskDelete(NULL);
}

static void ntp_dispatch_start(void)
{
    /* atomic_exchange returns the old value; if it was already true we skip. */
    if (atomic_exchange(&s_ntp_started, true)) return;

    BaseType_t ret = xTaskCreate(ntp_start_task, "ntp_start",
                                 4096, NULL,
                                 tskIDLE_PRIORITY + 1, NULL);
    if (ret != pdPASS) {
        ESP_LOGW(TAG, "xTaskCreate(ntp_start_task) failed -- NTP not started");
        atomic_store(&s_ntp_started, false);
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
 * Post-start radio tuning helpers
 *
 * apply_max_tx_power() caps the radio TX power when WIFI_MAX_TX_POWER is
 * defined in config.h.  Must be invoked immediately after every
 * esp_wifi_start() call site (enterprise + PSK + smart-mode psk/enterprise)
 * because the underlying IDF API requires the radio to be running.
 *
 * No-op when WIFI_MAX_TX_POWER is undefined -- safe to call from every site.
 *
 * Rationale: on boards with a small onboard ceramic antenna (ESP32-S3-Zero
 * in particular) full 21 dBm output couples back into the chip during
 * sustained TX bursts and corrupts WiFi RX.  Previously the cap was only
 * applied in wifi_mode_psk(), so the long-lived enterprise production
 * session ran uncapped -- exactly the regime the cap exists to fix.
 * -------------------------------------------------------------------------- */
/* redact_for_log -- write a short non-reversible-by-eye hash prefix of `in`
 * into `out` so a sensitive identifier (EAP identity, device CN, ...) can
 * appear in INFO-level logs without leaking the cleartext into the udp_log
 * mirror.
 *
 * Uses FNV-1a 64-bit (not cryptographic, but sufficient to prevent casual
 * disclosure in a log line).  A cryptographic prefix would require pulling
 * in mbedtls SHA-256 or wolfCrypt directly; on IDF 6.x mbedtls 4.x has
 * moved the legacy mbedtls/sha256.h interface behind PSA, making that more
 * intrusive than the threat justifies (the goal is "no cleartext identity
 * in the udp_log stream", not protection against an attacker with offline
 * compute).
 *
 * Output format: "h:" + 16 hex chars, null-terminated.  Requires out_sz >= 20.
 * On any failure (NULL out, tiny buffer, NULL input) the output becomes "h:?".
 */
static void redact_for_log(char *out, size_t out_sz,
                           const char *in, size_t in_len)
{
    if (!out || out_sz < 4) {
        if (out && out_sz > 0) out[0] = '\0';
        return;
    }
    if (!in || in_len == 0) {
        snprintf(out, out_sz, "h:?");
        return;
    }
    /* FNV-1a 64-bit. */
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < in_len; i++) {
        h ^= (uint64_t)(unsigned char)in[i];
        h *= 0x100000001b3ULL;
    }
    if (out_sz < 20) {
        snprintf(out, out_sz, "h:?");
        return;
    }
    snprintf(out, out_sz, "h:%016llx", (unsigned long long)h);
}

static void apply_max_tx_power(void)
{
#ifdef WIFI_MAX_TX_POWER
    int8_t cur = 0;
    esp_wifi_get_max_tx_power(&cur);
    esp_err_t pe = esp_wifi_set_max_tx_power((int8_t)WIFI_MAX_TX_POWER);
    if (pe == ESP_OK) {
        ESP_LOGI(TAG, "TX power capped: %d -> %d (0.25 dBm units)",
                 cur, (int)WIFI_MAX_TX_POWER);
    } else {
        ESP_LOGW(TAG, "esp_wifi_set_max_tx_power(%d): %s",
                 (int)WIFI_MAX_TX_POWER, esp_err_to_name(pe));
    }
#endif
}

/* --------------------------------------------------------------------------
 * Reconnect backoff timer
 *
 * Deferring the esp_wifi_connect() call to a FreeRTOS one-shot timer keeps
 * the system event task unblocked during the backoff window.  Blocking the
 * event task with vTaskDelay() stalls ALL WIFI_EVENT and IP_EVENT dispatch
 * for the delay's duration -- including the STA_GOT_IP we are waiting for
 * if the driver reconnects via another path, and any subsequent disconnect
 * events (which would otherwise queue up and overflow).
 *
 * Race-safety: the timer-handle pointer is created exactly once (under the
 * double-init guard) and is only written-once.  Start/stop calls and the
 * timer callback all run from various tasks but operate on FreeRTOS timer
 * APIs that are themselves task-safe.  When a fresh disconnect arrives
 * while a backoff is pending, xTimerStop+xTimerChangePeriod+xTimerStart
 * atomically replaces the pending fire (xTimerChangePeriod implicitly
 * starts the timer; but we call xTimerStop first so the callback cannot
 * race with the change).  If a STA_CONNECTED/GOT_IP arrives while the
 * timer is pending we stop it explicitly so the deferred connect doesn't
 * fire after we are already up.
 * -------------------------------------------------------------------------- */
static TimerHandle_t s_reconnect_timer = NULL;

static void reconnect_timer_cb(TimerHandle_t t)
{
    (void)t;
    /* The timer callback runs in the timer-service task.  If we are
     * already connected (s_retry_num reset to 0 by the success path),
     * skip the connect to avoid a needless extra association attempt. */
    EventBits_t bits = s_wifi_event_group
        ? xEventGroupGetBits(s_wifi_event_group) : 0;
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGD(TAG, "reconnect_timer_cb: already connected -- skipping");
        return;
    }
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        /* Most likely ESP_ERR_WIFI_CONN if the driver is in a transitional
         * state.  Log + leave; the next disconnect event will re-arm us. */
        ESP_LOGW(TAG, "reconnect_timer_cb: esp_wifi_connect: %s",
                 esp_err_to_name(err));
    }
}

static void reconnect_timer_schedule(uint32_t delay_ms)
{
    if (!s_reconnect_timer) {
        /* Should not happen: the timer is created in wifi_init_sta /
         * wifi_smart_init_common before the event handler is registered.
         * If it ever does, fall back to immediate connect so we don't
         * silently stop retrying. */
        ESP_LOGW(TAG, "reconnect_timer_schedule: timer not created -- "
                      "calling esp_wifi_connect immediately");
        esp_wifi_connect();
        return;
    }
    /* Stop first to cancel any pending fire, then set the new period and
     * start.  xTimerChangePeriod auto-starts but doesn't cancel a pending
     * callback that has already been queued by the timer service; the
     * explicit stop avoids that corner. */
    if (delay_ms == 0) delay_ms = 1;  /* xTimerChangePeriod rejects 0 */
    xTimerStop(s_reconnect_timer, 0);
    xTimerChangePeriod(s_reconnect_timer, pdMS_TO_TICKS(delay_ms), 0);
    /* xTimerChangePeriod implicitly starts a stopped timer; xTimerStart
     * is a no-op safety belt against future FreeRTOS behaviour changes. */
    xTimerStart(s_reconnect_timer, 0);
}

static void reconnect_timer_cancel(void)
{
    if (s_reconnect_timer) xTimerStop(s_reconnect_timer, 0);
}

static void reconnect_timer_create_once(void)
{
    if (s_reconnect_timer) return;
    s_reconnect_timer = xTimerCreate(
        "wifi_reconn",
        pdMS_TO_TICKS(1000),   /* placeholder; real period set on schedule */
        pdFALSE,               /* one-shot */
        NULL,
        reconnect_timer_cb);
    if (!s_reconnect_timer) {
        ESP_LOGW(TAG, "Failed to create reconnect-backoff timer -- "
                      "falling back to immediate reconnects (no backoff)");
    }
}

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
            /* Cancel any pending deferred reconnect: L2 is back up, so a
             * stale fire would just bounce the link. */
            reconnect_timer_cancel();

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
# ifdef WIFI_ENTERPRISE_SSID
            if (s_psk_bootstrap_active) {
#  ifdef USE_STATIC_IPV4_BOOTSTRAP
                /* Bootstrap network has its own static IP config. */
                apply_static_ipv4_bootstrap();
                /* Log and signal immediately -- no IP event will follow. */
                {
                    esp_netif_ip_info_t ip;
                    if (esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK) {
                        ESP_LOGI(TAG, "IP address : " IPSTR, IP2STR(&ip.ip));
                        ESP_LOGI(TAG, "Netmask    : " IPSTR, IP2STR(&ip.netmask));
                        ESP_LOGI(TAG, "Gateway    : " IPSTR, IP2STR(&ip.gw));
                    }
                }
                atomic_store(&s_retry_num, 0);
                xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
                mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
                ntp_dispatch_start();
#endif
#if defined(UDP_LOG_HOST) && defined(UDP_LOG_PORT)
                udp_log_init();
#endif
#  else  /* USE_STATIC_IPV4_BOOTSTRAP not defined */
                /* PSK bootstrap is transient and may be on a different subnet
                 * from the production enterprise network -- use DHCP regardless
                 * of the USE_STATIC_IPV4 setting.  Ensure the DHCP client is
                 * running.
                 *
                 * E2E note: the expected behaviour (not testable without a real
                 * two-subnet network) is that DHCP assigns a lease on the PSK
                 * subnet, the on_ip() callback runs (NTP sync / SCEP), and then
                 * wifi_mode_psk() calls esp_wifi_stop().  On the subsequent
                 * wifi_mode_enterprise() call s_psk_bootstrap_active is false,
                 * so apply_static_ipv4_enterprise() runs normally for the
                 * enterprise interface. */
                esp_netif_dhcpc_start(s_sta_netif);
                /* No IP yet -- let IP_EVENT_STA_GOT_IP fire later. */
#  endif /* USE_STATIC_IPV4_BOOTSTRAP */
            } else {
# endif /* WIFI_ENTERPRISE_SSID */
            /* Apply static address at L2-connect time so the routing table
             * is populated before we signal success. */
            apply_static_ipv4_enterprise();
            /* Log and signal immediately -- no IP event will follow. */
            {
                esp_netif_ip_info_t ip;
                if (esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK) {
                    ESP_LOGI(TAG, "IP address : " IPSTR, IP2STR(&ip.ip));
                    ESP_LOGI(TAG, "Netmask    : " IPSTR, IP2STR(&ip.netmask));
                    ESP_LOGI(TAG, "Gateway    : " IPSTR, IP2STR(&ip.gw));
                }
            }
            atomic_store(&s_retry_num, 0);
            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
            mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
            ntp_dispatch_start();
#endif
#if defined(UDP_LOG_HOST) && defined(UDP_LOG_PORT)
            udp_log_init();
#endif
# ifdef WIFI_ENTERPRISE_SSID
            } /* end else (not psk_bootstrap_active) */
# endif /* WIFI_ENTERPRISE_SSID */
#endif /* USE_STATIC_IPV4 */

            /* Bring up IPv6 now that L2 is up.
             *
             * Enterprise path: follow IPV6_MODE.  On the PSK bootstrap network
             * with USE_STATIC_IPV4_BOOTSTRAP, follow BOOTSTRAP_IPV6_MODE
             * (defaults to DISABLED -- static IPv6 belongs to the enterprise
             * interface, not the transient bootstrap VLAN).  SLAAC/DHCPv6
             * modes still bring up link-local on the bootstrap path. */
#if IPV6_MODE != IPV6_MODE_DISABLED && defined(CONFIG_LWIP_IPV6)
# if defined(WIFI_ENTERPRISE_SSID)
            if (s_psk_bootstrap_active) {
#  if defined(USE_STATIC_IPV4_BOOTSTRAP) && \
      BOOTSTRAP_IPV6_MODE != IPV6_MODE_DISABLED
                ipv6_bring_up_bootstrap();
#  endif /* USE_STATIC_IPV4_BOOTSTRAP && BOOTSTRAP_IPV6_MODE != DISABLED */
                /* When BOOTSTRAP_IPV6_MODE is DISABLED (or bootstrap static not
                 * requested), skip IPv6 on the bootstrap interface entirely. */
            } else {
                ipv6_bring_up();
            }
# else  /* no WIFI_ENTERPRISE_SSID -- single-network modes A/B */
            ipv6_bring_up();
# endif /* WIFI_ENTERPRISE_SSID */
#endif /* IPV6_MODE != IPV6_MODE_DISABLED */

        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            wifi_event_sta_disconnected_t *ev =
                (wifi_event_sta_disconnected_t *)event_data;

            /* Clear the connected bit so callers that poll it see the drop. */
            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
            /* L2 link is down; pause the watchdog until we re-associate. */
            if (s_dhcp_watchdog) xTimerStop(s_dhcp_watchdog, 0);
#endif

            /* ALWAYS consume the cert-renewal flag here, regardless of
             * reason code.  See the s_eap_creds_just_rotated declaration
             * for the lifecycle.  Without this, the flag could leak when
             * the disconnect that follows cert_renewer's
             * esp_wifi_disconnect() surfaces with a reason other than
             * ASSOC_LEAVE (RADIUS reject -> AUTH_FAIL, AP went away ->
             * BEACON_TIMEOUT, ...).  A future, unrelated ASSOC_LEAVE
             * would then spuriously trigger the post-renewal reconnect. */
            bool rotated_expected = atomic_exchange(
                &s_eap_creds_just_rotated, false);

            /* Reason 8 (ASSOC_LEAVE) is the disconnect that fires when we
             * call esp_wifi_stop() ourselves to transition between PSK
             * bootstrap and enterprise.  The next wifi_mode_* call will
             * start a fresh session; auto-reconnect here would race it. */
            if (ev->reason == WIFI_REASON_ASSOC_LEAVE) {
                if (rotated_expected) {
                    /* cert_renewer rotated creds and called
                     * esp_wifi_disconnect() to force 802.1X re-auth.
                     * smart_eap_apply_creds() pushed the new certificates
                     * into the supplicant; the connect below will use them. */
                    ESP_LOGI(TAG, "disconnected (reason %d -- post-renewal: "
                                  "reconnecting with new EAP creds)",
                             ev->reason);
                    atomic_store(&s_retry_num, 0);
                    reconnect_timer_cancel();
                    esp_err_t cerr = esp_wifi_connect();
                    if (cerr != ESP_OK) {
                        ESP_LOGW(TAG, "post-renewal esp_wifi_connect: %s",
                                 esp_err_to_name(cerr));
                    }
                    goto disc_done;
                }
                ESP_LOGI(TAG, "disconnected (reason %d -- planned teardown)",
                         ev->reason);
                reconnect_timer_cancel();
                goto disc_done;
            }

            /* Classify the disconnect reason: security-relevant failures
             * (auth, handshake, key-management, 802.1X) use the longer
             * 5-minute cap so RADIUS rejections / MIC failures / cipher
             * mismatches don't flood upstream audit logs or accelerate
             * brute-force attempts.  See wifi_backoff.c for the full list
             * of security-relevant reason codes and their rationales. */
            bool security_fail = wifi_backoff_is_security_failure(ev->reason);

            const bool infinite = (WIFI_MAX_RETRY == 0);
            int cur_retry = atomic_load(&s_retry_num);
            if (infinite || cur_retry < WIFI_MAX_RETRY) {
                /* atomic_fetch_add returns the previous value; we want the
                 * post-increment for the backoff/log computations below. */
                cur_retry = atomic_fetch_add(&s_retry_num, 1) + 1;

                uint32_t delay_ms = wifi_backoff_compute_ms(
                    cur_retry, security_fail, esp_random());

                /* Rate-limit the disconnect log: every event for the
                 * first 5 retries, then 1-of-10 to keep the trail without
                 * flooding. */
                bool emit = (cur_retry <= 5) || ((cur_retry % 10) == 0);
                if (emit) {
                    const char *kind = security_fail ? "AUTH" : "LINK";
                    if (infinite) {
                        ESP_LOGW(TAG,
                            "%s disconnect (reason %d), retry %d (infinite), "
                            "backoff %u ms",
                            kind, ev->reason, cur_retry, (unsigned)delay_ms);
                    } else {
                        ESP_LOGW(TAG,
                            "%s disconnect (reason %d), retry %d/%d, "
                            "backoff %u ms",
                            kind, ev->reason, cur_retry, WIFI_MAX_RETRY,
                            (unsigned)delay_ms);
                    }
                }

                /* Defer the reconnect to the timer-service task so the
                 * system event task stays free to dispatch other WiFi/IP
                 * events during the backoff window. */
                reconnect_timer_schedule(delay_ms);
            } else {
                /* Signal permanent failure to wifi_init_sta()'s wait. */
                xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                ESP_LOGE(TAG, "gave up after %d retries (reason %d)",
                         WIFI_MAX_RETRY, ev->reason);

                /* RECONNECT_FOREVER: keep retrying even after signalling
                 * failure so we recover if the AP comes back later.  Use
                 * the LINK cap so we are not stuck at 5 min after an
                 * unrelated transient at the give-up boundary. */
                reconnect_timer_schedule(WIFI_BACKOFF_LINK_CAP_MS);
            }
        disc_done: ;
        }

    } else if (event_base == IP_EVENT) {

        if (event_id == IP_EVENT_STA_GOT_IP) {
#if !defined(USE_STATIC_IPV4) || defined(WIFI_ENTERPRISE_SSID)
            /* DHCPv4 path: print the assigned address and signal ready.
             *
             * When USE_STATIC_IPV4 is defined without WIFI_ENTERPRISE_SSID
             * (Mode A/B static), this event may still fire when esp-netif
             * raises it on netif IP change, but we already logged and
             * signalled in the STA_CONNECTED handler, so skip it.
             *
             * When WIFI_ENTERPRISE_SSID is also defined (Mode B+/C smart),
             * the PSK bootstrap path runs DHCP when USE_STATIC_IPV4_BOOTSTRAP
             * is not set (s_psk_bootstrap_active + no bootstrap static); in
             * that case this event carries the DHCP-assigned bootstrap IP and
             * must signal CONNECTED_BIT.
             *
             * When USE_STATIC_IPV4_BOOTSTRAP is also set, the bootstrap path
             * already logged and signalled in STA_CONNECTED (same as the
             * enterprise static path), so skip this event for both cases. */
# if defined(USE_STATIC_IPV4) && defined(WIFI_ENTERPRISE_SSID)
            /* Skip for enterprise static (not bootstrap) OR when bootstrap
             * also has a static address already applied. */
            if (!s_psk_bootstrap_active) goto ip_event_done;
#  ifdef USE_STATIC_IPV4_BOOTSTRAP
            /* Bootstrap static path already handled in STA_CONNECTED. */
            goto ip_event_done;
#  endif
# endif
            {
            ip_event_got_ip_t *ev = (ip_event_got_ip_t *)event_data;

            /* ----------------------------------------------------------------
             * Print the DHCP-assigned IP to the UART log -- the primary
             * discovery mechanism for v1 (no mDNS).  SSH task can start now.
             * ---------------------------------------------------------------- */
            ESP_LOGI(TAG, "IP address : " IPSTR, IP2STR(&ev->ip_info.ip));
            ESP_LOGI(TAG, "Netmask    : " IPSTR, IP2STR(&ev->ip_info.netmask));
            ESP_LOGI(TAG, "Gateway    : " IPSTR, IP2STR(&ev->ip_info.gw));

#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
            /* DHCP succeeded -- disarm the watchdog. */
            if (s_dhcp_watchdog) xTimerStop(s_dhcp_watchdog, 0);
#endif

            atomic_store(&s_retry_num, 0);
            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
#if !defined(BRIDGE_LOOPBACK) && defined(MDNS_ENABLE)
            mdns_dispatch_start();
#endif
#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)
            ntp_dispatch_start();
#endif
#if defined(UDP_LOG_HOST) && defined(UDP_LOG_PORT)
            udp_log_init();
#endif
            }
# if defined(USE_STATIC_IPV4) && defined(WIFI_ENTERPRISE_SSID)
            ip_event_done: ;
# endif
#endif /* !USE_STATIC_IPV4 || WIFI_ENTERPRISE_SSID */

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
    bool bl_already = atomic_exchange(&s_wifi_inited, true);
    if (bl_already) {
        ESP_LOGW(TAG, "BRIDGE_LOOPBACK: wifi already inited; skipping");
        return ESP_ERR_INVALID_STATE;
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();
    return ESP_OK;
#endif

    /* 1. Create the EventGroup used to synchronise with app_main / ssh_task.
     * wifi_event_group_reset() deletes any stale handle first to avoid a leak
     * if this function is somehow entered twice. */
    wifi_event_group_reset();

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

    /* Create the reconnect-backoff timer before any event handler is
     * registered so the disconnect handler can schedule it from event 0. */
    reconnect_timer_create_once();

    /* 2. Initialise the TCP/IP stack and create the default event loop.
     *    Order matters: esp_netif_init() before esp_event_loop_create_default()
     *    before esp_netif_create_default_wifi_sta().
     *    Double-init guard: skip these (and esp_wifi_init below) if a
     *    previous wifi_init_* already brought them up. */
    bool already_inited = atomic_exchange(&s_wifi_inited, true);
    if (already_inited) {
        ESP_LOGW(TAG, "wifi already inited; skipping netif/event/wifi init");
        return ESP_ERR_INVALID_STATE;
    }
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

    /* Explicit country code so RF state for channels 12-13 is fully set up
     * at init time.  Default is "01" (world / channels 1-11) which lets the
     * chip associate to ch12/13 APs via passive scan but can leave the RX
     * state machine half-initialised for those channels -- on some S3 dies
     * the first burst of TCP traffic on channel 13 then crashes ppRxFragmentProc.
     * Define WIFI_COUNTRY_CODE in config.h with a 2-char ISO country code
     * (e.g. "RO", "DE", "US") to opt in. */
#ifdef WIFI_COUNTRY_CODE
    {
        esp_err_t cc_err = esp_wifi_set_country_code(WIFI_COUNTRY_CODE, true);
        if (cc_err == ESP_OK) {
            ESP_LOGI(TAG, "WiFi country code set to \"%s\" (ieee80211d enabled)",
                     WIFI_COUNTRY_CODE);
        } else {
            ESP_LOGW(TAG, "esp_wifi_set_country_code(\"%s\"): %s",
                     WIFI_COUNTRY_CODE, esp_err_to_name(cc_err));
        }
    }
#endif

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
    {
        size_t ca_len  = (size_t)(eap_ca_pem_end  - eap_ca_pem_start);
        size_t crt_len = (size_t)(eap_client_crt_end - eap_client_crt_start);
        size_t key_len = (size_t)(eap_client_key_end - eap_client_key_start);
        if (ca_len < EAP_CA_MIN_BYTES) {
            ESP_LOGE(TAG, "EAP cert blob too small: ca.pem got %u need %u",
                     (unsigned)ca_len, (unsigned)EAP_CA_MIN_BYTES);
            return ESP_ERR_INVALID_SIZE;
        }
        if (crt_len < EAP_CRT_MIN_BYTES) {
            ESP_LOGE(TAG, "EAP cert blob too small: client.crt got %u need %u",
                     (unsigned)crt_len, (unsigned)EAP_CRT_MIN_BYTES);
            return ESP_ERR_INVALID_SIZE;
        }
        if (key_len < EAP_KEY_MIN_BYTES) {
            ESP_LOGE(TAG, "EAP cert blob too small: client.key got %u need %u",
                     (unsigned)key_len, (unsigned)EAP_KEY_MIN_BYTES);
            return ESP_ERR_INVALID_SIZE;
        }
    }

    {
        char id_redacted[24];
        redact_for_log(id_redacted, sizeof(id_redacted),
                       EAP_IDENTITY, strlen(EAP_IDENTITY));
        ESP_LOGD(TAG, "Configuring EAP-TLS (identity: %s)", EAP_IDENTITY);
        /* INFO mirrors over udp_log; emit only the redacted form there. */
        ESP_LOGI(TAG, "Configuring EAP-TLS (identity %s)", id_redacted);
    }

    ESP_ERROR_CHECK(esp_eap_client_set_identity(
        (const unsigned char *)EAP_IDENTITY, strlen(EAP_IDENTITY)));

#ifdef EAP_ANONYMOUS_IDENTITY
    /* Outer EAP identity sent in clear before the TLS tunnel is set up.
     * Recommended for RADIUS deployments that route by NAI realm
     * (e.g. "anonymous@realm").  Without this, the inner identity
     * (set via esp_eap_client_set_identity above) leaks during phase 1. */
    ESP_ERROR_CHECK(esp_eap_client_set_anonymous_identity(
        (const unsigned char *)EAP_ANONYMOUS_IDENTITY,
        strlen(EAP_ANONYMOUS_IDENTITY)));
    ESP_LOGI(TAG, "EAP outer NAI configured");
#endif

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

    /* Cap TX power immediately after the radio is running.  This applies to
     * both the PSK and the WIFI_USE_ENTERPRISE branch -- the previous
     * implementation only capped on the PSK helper, so the long-lived
     * enterprise session ran at full power on antenna-limited boards. */
    apply_max_tx_power();

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

#ifdef WIFI_USE_ENTERPRISE
/* Parse the embedded client.crt and return true iff notAfter is closer
 * than CERT_REENROLL_THRESHOLD_SEC from `now`.  Returns false on any
 * parse error -- a parse failure shouldn't block the EAP-TLS attempt
 * (the supplicant will emit its own diagnostic).  Used by Mode B+'s
 * wifi_init_enterprise_bootstrap to detect when the embedded cert has
 * aged past validity (M8 fix).
 *
 * M1.A: mbedtls_x509_time fields are UTC.  mktime() interprets struct tm
 * as LOCAL time via the process TZ (set by NTP init to e.g. EET-2EEST),
 * which would compute expiry 2-3 hours early and trigger premature
 * re-enrollment.  We use Howard Hinnant's days-from-civil formula
 * (the same algorithm used by cred_store's x509_time_to_epoch) to
 * convert UTC fields to a POSIX epoch without any TZ interpretation.
 *
 * M1.F: the embedded cert bytes never change at runtime, so parsing on
 * every NTP-sync iteration is wasteful.  We cache the valid_to epoch in
 * a file-static variable and parse only on the first call.  The cached
 * value depends only on cert bytes (not on system time), so it remains
 * correct across NTP time-jumps. */
static time_t s_embedded_cert_valid_to_epoch = -1;   /* -1 = not yet parsed */

static bool eval_embedded_client_cert_expired(time_t now)
{
    /* Lazy-initialise once: parse the cert and cache the notAfter epoch. */
    if (s_embedded_cert_valid_to_epoch < 0) {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        size_t crt_len = (size_t)(eap_client_crt_end - eap_client_crt_start);
        int rc = mbedtls_x509_crt_parse(&crt, eap_client_crt_start, crt_len);
        if (rc != 0) {
            ESP_LOGW(TAG, "[b+] mbedtls_x509_crt_parse(client.crt): %d", rc);
            mbedtls_x509_crt_free(&crt);
            /* Leave s_embedded_cert_valid_to_epoch at -1; return false so
             * a parse failure doesn't permanently block the EAP-TLS attempt. */
            return false;
        }

        /* Convert UTC notAfter using Howard Hinnant's date-to-epoch formula.
         * This is equivalent to timegm() but without the TZ lookup that
         * mktime() performs.  newlib on ESP-IDF does not export timegm(). */
        const mbedtls_x509_time *vt = &crt.valid_to;
        int y = vt->year;
        int m = vt->mon;
        int d = vt->day;
        y -= (m <= 2);
        int era = (y >= 0 ? y : y - 399) / 400;
        unsigned yoe = (unsigned)(y - era * 400);
        unsigned doy = (153U * (unsigned)(m > 2 ? m - 3 : m + 9) + 2U) / 5U
                       + (unsigned)d - 1U;
        unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
        int64_t days  = (int64_t)era * 146097LL + (int64_t)doe - 719468LL;
        int64_t epoch = days * 86400LL
                      + (int64_t)vt->hour * 3600LL
                      + (int64_t)vt->min  * 60LL
                      + (int64_t)vt->sec;

        mbedtls_x509_crt_free(&crt);
        s_embedded_cert_valid_to_epoch = (time_t)epoch;
        ESP_LOGI(TAG, "[b+] embedded client.crt notAfter epoch cached: %lld",
                 (long long)s_embedded_cert_valid_to_epoch);
    }

    if (s_embedded_cert_valid_to_epoch <= 0) {
        /* Implausible epoch from parse -- don't block on it. */
        return false;
    }

    return (s_embedded_cert_valid_to_epoch - now) < (time_t)CERT_REENROLL_THRESHOLD_SEC;
}
#endif /* WIFI_USE_ENTERPRISE */

/* When SCEP returns pkiStatus=PENDING (the CA queued the request for manual
 * NDES approval), wait this many ms before the next enrollment attempt.
 * Default 30 minutes -- an approver realistically takes minutes to hours, and
 * each premature retry consumes a new NDES transactionID + audit-log entry.
 * Override in config.h if your approval workflow is faster/slower. */
#ifndef SCEP_PENDING_RETRY_DELAY_MS
# define SCEP_PENDING_RETRY_DELAY_MS  (30u * 60u * 1000u)
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
    atomic_store(&s_retry_num, 0);

    /* Mark PSK bootstrap as active BEFORE esp_wifi_start() so the event
     * handler sees the flag when WIFI_EVENT_STA_CONNECTED fires.  This
     * causes USE_STATIC_IPV4 builds to use DHCP on this transient network
     * instead of trying to apply the production static address. */
    s_psk_bootstrap_active = true;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Cap TX power (Zero ceramic antenna mitigation).  See apply_max_tx_power
     * comments for rationale.  Must run AFTER esp_wifi_start(). */
    apply_max_tx_power();

    /* Disable 802.11 modem-sleep PS.  CONFIG_PM_ENABLE=n only disables the
     * ESP-IDF CPU power manager; the WiFi driver's own beacon-window PS is
     * a separate switch.  Default is WIFI_PS_MIN_MODEM, which on the Zero
     * (FH4R2 v0.2) can trigger an IntegerDivideByZero in pm_get_tbtt_count
     * inside libpp.a after a flaky beacon -- the TBTT divisor is briefly 0
     * during the recovery window and the divide instruction faults.
     * WIFI_PS_NONE keeps the radio fully active and avoids the math. */
    {
        esp_err_t ps_err = esp_wifi_set_ps(WIFI_PS_NONE);
        if (ps_err == ESP_OK) {
            ESP_LOGI(TAG, "802.11 power save: NONE (radio always on)");
        } else {
            ESP_LOGW(TAG, "esp_wifi_set_ps(WIFI_PS_NONE): %s",
                     esp_err_to_name(ps_err));
        }
    }

    /* Wait for IP or failure.  WIFI_MAX_RETRY=0 means infinite here too. */
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        portMAX_DELAY);

    if (!(bits & WIFI_CONNECTED_BIT)) {
        ESP_LOGE(TAG, "[smart] PSK connect to \"%s\" failed", ssid);
        s_psk_bootstrap_active = false;
        esp_wifi_stop();
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "[smart] PSK connected to \"%s\"", ssid);
    esp_err_t result = on_ip ? on_ip() : ESP_OK;

    esp_wifi_stop();
    s_psk_bootstrap_active = false;
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

    /* M1.D: cap num_of_servers against CONFIG_LWIP_SNTP_MAX_SERVERS so we
     * don't write beyond the cfg.servers[] array bound.  Mirror the same
     * cap + warn pattern used in ntp_start_task. */
    if (n_servers > CONFIG_LWIP_SNTP_MAX_SERVERS) {
        for (size_t i = CONFIG_LWIP_SNTP_MAX_SERVERS; i < n_servers; i++) {
            ESP_LOGW(TAG, "[smart] NTP server[%u] \"%s\" dropped (exceeds "
                          "CONFIG_LWIP_SNTP_MAX_SERVERS=%d)",
                     (unsigned)i, servers[i], CONFIG_LWIP_SNTP_MAX_SERVERS);
        }
    }
    const size_t n_servers_capped = (n_servers < (size_t)CONFIG_LWIP_SNTP_MAX_SERVERS)
                                    ? n_servers
                                    : (size_t)CONFIG_LWIP_SNTP_MAX_SERVERS;

    esp_sntp_config_t cfg = {
        .smooth_sync                = false,
        .server_from_dhcp           = false,
        .wait_for_sync              = true,
        .start                      = true,
        .sync_cb                    = NULL,
        .renew_servers_after_new_IP = false,
        .ip_event_to_renew          = IP_EVENT_STA_GOT_IP,
        .index_of_first_server      = 0,
        .num_of_servers             = n_servers_capped,
    };
    for (size_t i = 0; i < n_servers_capped; i++) {
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

    TickType_t sntp_start = xTaskGetTickCount();
    TickType_t sntp_timeout = pdMS_TO_TICKS((uint32_t)BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC * 1000u);
    while ((xTaskGetTickCount() - sntp_start) < sntp_timeout) {
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
     * NotBefore after enrollment below.
     *
     * M15: before we kick off HTTPS to the SCEP server, set a build-time
     * floor on the clock.  Without this, mbedTLS's X.509 time validation
     * during the TLS handshake runs with time(NULL) == 0 (epoch) and accepts
     * ANY notBefore/notAfter (including long-expired or future certs).
     * The floor below is the firmware compile time -- best-effort, not a
     * substitute for NTP, but it tightens the validation window from
     * "all of history" to "after this firmware was built". */
    {
        time_t now = time(NULL);
        if (now < SCEP_NO_NTP_BUILD_EPOCH) {
            struct timeval tv = {
                .tv_sec  = (time_t)SCEP_NO_NTP_BUILD_EPOCH,
                .tv_usec = 0,
            };
            if (settimeofday(&tv, NULL) == 0) {
                ESP_LOGW(TAG, "[smart] no-NTP mode: clock floor set to "
                              "firmware build epoch %lld -- TLS time "
                              "validation is best-effort until enrollment "
                              "issuance time is applied",
                         (long long)SCEP_NO_NTP_BUILD_EPOCH);
            } else {
                ESP_LOGW(TAG, "[smart] no-NTP mode: settimeofday(build_epoch) "
                              "failed -- TLS time validation will accept "
                              "any cert validity window");
            }
        }
    }
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
    if (enroll_err == ESP_ERR_SCEP_PENDING) {
        /* CA queued the request for manual approval -- a fresh enrollment
         * now would just flood NDES with new transactionIDs.  Propagate the
         * distinct value so the wifi_init_smart loop can apply a long
         * (~30 min) backoff before re-attempting. */
        ESP_LOGW(TAG, "[smart] SCEP enrollment PENDING (awaiting CA approval) "
                      "-- caller will back off");
        return ESP_ERR_SCEP_PENDING;
    }
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
        /* M1.E: log clearly when the allocation fails so the subsequent
         * "clock unchanged" warning is not the only diagnostic visible. */
        if (!fresh_creds) {
            ESP_LOGW(TAG, "[smart] no-NTP mode: calloc(%u B) for cred_store_t "
                          "failed -- cannot set clock from cert NotBefore",
                     (unsigned)sizeof(cred_store_t));
        }
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
                if (settimeofday(&tv, NULL) != 0) {
                    ESP_LOGE(TAG,
                             "[smart] no-NTP mode: settimeofday failed -- "
                             "clock unchanged, treating as unsynced");
                } else {
                    ESP_LOGI(TAG,
                             "[smart] no-NTP mode: local time set to cert NotBefore"
                             " = %llu", (unsigned long long)not_before_epoch);
                }
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
    {
        char id_redacted[24];
        redact_for_log(id_redacted, sizeof(id_redacted),
                       EAP_IDENTITY, strlen(EAP_IDENTITY));
        ESP_LOGD(TAG, "[smart] configuring EAP-TLS (identity: %s)", EAP_IDENTITY);
        ESP_LOGI(TAG, "[smart] configuring EAP-TLS (identity %s)", id_redacted);
    }

    {
        esp_err_t err = esp_eap_client_set_identity(
            (const unsigned char *)EAP_IDENTITY, strlen(EAP_IDENTITY));
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "[smart] esp_eap_client_set_identity failed: %s",
                     esp_err_to_name(err));
            return ESP_FAIL;
        }
#ifdef EAP_ANONYMOUS_IDENTITY
        /* See main path: outer/anonymous identity for NAI-realm routing. */
        err = esp_eap_client_set_anonymous_identity(
            (const unsigned char *)EAP_ANONYMOUS_IDENTITY,
            strlen(EAP_ANONYMOUS_IDENTITY));
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "[smart] esp_eap_client_set_anonymous_identity failed: %s",
                     esp_err_to_name(err));
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "[smart] EAP outer NAI configured");
#endif
    }

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

        {
            esp_err_t err = esp_eap_client_set_ca_cert(
                eap_ca_pem_start,
                eap_ca_pem_end - eap_ca_pem_start);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "[smart] set_ca_cert (embedded) failed: %s",
                         esp_err_to_name(err));
                return ESP_FAIL;
            }
            err = esp_eap_client_set_certificate_and_key(
                eap_client_crt_start,
                eap_client_crt_end - eap_client_crt_start,
                eap_client_key_start,
                eap_client_key_end - eap_client_key_start,
                NULL, 0);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "[smart] set_certificate_and_key (embedded) failed: %s",
                         esp_err_to_name(err));
                return ESP_FAIL;
            }
        }
#else
        ESP_LOGE(TAG, "[smart] no NVS creds and no embedded certs -- "
                      "EAP-TLS will fail");
        return ESP_FAIL;
#endif
    }

    /* EAP-TLS only: with just cert+key configured the IDF supplicant
     * auto-selects EAP-TLS (no method-restriction API in IDF 5.4.1). */
    {
        esp_err_t err = esp_wifi_sta_enterprise_enable();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "[smart] esp_wifi_sta_enterprise_enable failed: %s",
                     esp_err_to_name(err));
            return ESP_FAIL;
        }
    }
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
    atomic_store(&s_retry_num, 0);

    /* Clear PSK-bootstrap flag BEFORE esp_wifi_start() so the event handler
     * sees that we are now on the enterprise (production) network and applies
     * USE_STATIC_IPV4 addressing if configured. */
    s_psk_bootstrap_active = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    /* esp_wifi_set_config logs a benign "Password length is zero, but
     * authmode threshold is 5 ..." warning when configuring EAP-TLS
     * (password is unused in EAP).  Drop the wifi log level briefly so
     * that one line stays out of the boot capture, then restore. */
    esp_log_level_t prev_wifi_level = esp_log_level_get("wifi");
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    esp_err_t set_cfg_err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_log_level_set("wifi", prev_wifi_level);
    ESP_ERROR_CHECK(set_cfg_err);
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Cap TX power for the long-lived enterprise session (Zero antenna
     * mitigation).  Must run AFTER esp_wifi_start(). */
    apply_max_tx_power();

    /* Saturate the ms product at UINT32_MAX before passing to pdMS_TO_TICKS to
     * prevent overflow for timeout_sec >= 4294968 s (unlikely in practice but
     * the guard ensures correctness regardless of the configured value). */
    TickType_t wait;
    if (timeout_sec == 0) {
        wait = portMAX_DELAY;
    } else {
        uint64_t ms64 = (uint64_t)timeout_sec * 1000u;
        uint32_t ms32 = (ms64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)ms64;
        wait = pdMS_TO_TICKS(ms32);
    }

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
 * Idempotent: on a second call this function reuses the cached handler
 * instances from the first successful init and writes them to the
 * out-parameters.  Callers can therefore call us unconditionally and still
 * pass valid handles to esp_event_handler_instance_unregister later.
 *
 * Returns ESP_OK on success (including the already-inited reuse path);
 * aborts via configASSERT / ESP_ERROR_CHECK on any unrecoverable setup
 * failure that should never happen at runtime.  Returns ESP_ERR_INVALID_ARG
 * if either out-parameter pointer is NULL. */
static esp_event_handler_instance_t s_cached_inst_wifi = NULL;
static esp_event_handler_instance_t s_cached_inst_ip   = NULL;

static esp_err_t wifi_smart_init_common(
    esp_event_handler_instance_t *out_inst_wifi,
    esp_event_handler_instance_t *out_inst_ip)
{
    if (!out_inst_wifi || !out_inst_ip) return ESP_ERR_INVALID_ARG;

    /* 1. Double-init guard FIRST.  Earlier revisions reset the event group
     * before this check, which deleted-and-recreated the group on every
     * call even when we then bailed out without doing the rest of the
     * init -- leaking semantics for any task holding a handle to the
     * original group.  Check the guard first so the destructive
     * wifi_event_group_reset() runs only on the genuine first init. */
    bool already_inited = atomic_exchange(&s_wifi_inited, true);
    if (already_inited) {
        ESP_LOGW(TAG, "[smart] wifi already inited; reusing cached handles");
        *out_inst_wifi = s_cached_inst_wifi;
        *out_inst_ip   = s_cached_inst_ip;
        return ESP_OK;
    }

    /* 2. Shared resources (event group, DHCP watchdog). */
    wifi_event_group_reset();

#if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
    s_dhcp_watchdog = xTimerCreate(
        "dhcp_wd",
        pdMS_TO_TICKS(DHCP_RETRY_TIMEOUT_SEC * 1000),
        pdFALSE, NULL, dhcp_watchdog_cb);
    if (!s_dhcp_watchdog) {
        ESP_LOGW(TAG, "[smart] DHCP watchdog timer creation failed");
    }
#endif

    reconnect_timer_create_once();

    /* 3. TCP/IP stack + event loop. */
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

    /* Explicit country code: ESP-IDF defaults to "01" (world / channels 1-11),
     * which lets the chip associate to ch12/13 APs via passive scan but leaves
     * the RX state machine half-initialised for those channels.  On some S3
     * dies the first burst of TCP traffic on ch12/13 then crashes
     * ppRxFragmentProc.  Setting the country code explicitly with ieee80211d
     * fully reinitialises the RF subsystem for the configured band. */
#ifdef WIFI_COUNTRY_CODE
    {
        esp_err_t cc_err = esp_wifi_set_country_code(WIFI_COUNTRY_CODE, true);
        if (cc_err == ESP_OK) {
            ESP_LOGI(TAG, "[smart] WiFi country code set to \"%s\"",
                     WIFI_COUNTRY_CODE);
        } else {
            ESP_LOGW(TAG, "[smart] esp_wifi_set_country_code(\"%s\"): %s",
                     WIFI_COUNTRY_CODE, esp_err_to_name(cc_err));
        }
    }
#endif

    /* 5. Persistent event handlers (reconnect + IP logging).  Cache the
     * resulting instance handles so the idempotent reuse path above can
     * hand them back to subsequent callers. */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID,
        &wifi_event_handler, NULL, out_inst_wifi));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP,
        &wifi_event_handler, NULL, out_inst_ip));
    s_cached_inst_wifi = *out_inst_wifi;
    s_cached_inst_ip   = *out_inst_ip;

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
    esp_err_t init_err = wifi_smart_init_common(&inst_wifi, &inst_ip);
    if (init_err != ESP_OK) {
        ESP_LOGE(TAG, "[smart] wifi_smart_init_common failed: %s",
                 esp_err_to_name(init_err));
        return init_err;
    }

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
             *   c) enrollment failed (including PENDING -- the CA queued the
             *      request for manual approval; backoff applied below).
             *
             * In case (b) the cert is still valid (transient RADIUS failure).
             * Re-evaluate with updated state so we retry enterprise. */
            if (rc == ESP_ERR_SCEP_PENDING) {
                /* The CA returned pkiStatus=PENDING.  A retry now would just
                 * flood NDES with new transactionIDs (each one a fresh manual-
                 * approval ticket).  Wait SCEP_PENDING_RETRY_DELAY_MS before
                 * the next bootstrap pass.
                 *
                 * M1.C: if a cached cert is present AND not expired, the device
                 * should immediately attempt the enterprise path with that cert
                 * -- only the SCEP renewal is blocked, not existing credentials.
                 * We reload state below and let wifi_decide_next_step choose
                 * ENTERPRISE.  The long sleep only applies when there is no
                 * usable cert (i.e. the device genuinely cannot get online
                 * until the CA approves the new cert). */
                ESP_LOGW(TAG,
                    "[smart] SCEP returned PENDING -- backing off %u s before "
                    "next enrollment attempt",
                    (unsigned)(SCEP_PENDING_RETRY_DELAY_MS / 1000u));

                /* Reload state now (before the conditional sleep) so that
                 * cert_present / cert_expired reflect reality after the
                 * bootstrap pass updated NVS. */
                cert_present = (cred_store_load(creds_p) == ESP_OK);
                now = time(NULL);
                ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);
                if (cert_present && ntp_synced) {
                    time_t expiry = (time_t)creds_p->not_after;
                    cert_expired = (expiry - now) < (time_t)CERT_REENROLL_THRESHOLD_SEC;
                } else {
                    cert_expired = false;
                }

                if (cert_present && !cert_expired) {
                    /* The cached cert is still functional -- go straight to
                     * enterprise so the device comes up while waiting for CA
                     * approval.  The outer loop will reach WIFI_DECISION_ENTERPRISE
                     * on the next iteration without re-running SCEP first. */
                    ESP_LOGI(TAG,
                        "[smart] cached cert still valid -- attempting enterprise "
                        "during PENDING backoff; SCEP retry after %u s",
                        (unsigned)(SCEP_PENDING_RETRY_DELAY_MS / 1000u));
                    /* Reset enterprise attempts so the circuit-breaker doesn't
                     * gate us out immediately after a fresh state reload. */
                    enterprise_attempts = 0;
                    continue;
                }

                /* No usable cert -- sleep the full backoff before retrying. */
                ESP_LOGW(TAG,
                    "[smart] no usable cached cert -- sleeping %u s for CA approval",
                    (unsigned)(SCEP_PENDING_RETRY_DELAY_MS / 1000u));
                vTaskDelay(pdMS_TO_TICKS(SCEP_PENDING_RETRY_DELAY_MS));
            } else if (rc != ESP_OK) {
                ESP_LOGE(TAG,
                         "[smart] bootstrap full pass failed (PSK or SCEP) -- "
                         "retrying enterprise anyway");
            }
            /* Reload creds in case partial enrollment wrote something. */
            cert_present = (cred_store_load(creds_p) == ESP_OK);
            now = time(NULL);
            ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);
            /* Re-check expiry now that time may be synced. */
            if (cert_present && ntp_synced) {
                time_t expiry = (time_t)creds_p->not_after;
                cert_expired = (expiry - now) < (time_t)CERT_REENROLL_THRESHOLD_SEC;
            } else {
                cert_expired = false;
            }
            /* Reset enterprise attempt counter only when enrollment actually
             * produced fresh credentials (rc == ESP_OK AND creds are now
             * present).  A permanently misconfigured RADIUS server must not
             * get its circuit breaker reset on each bootstrap pass that merely
             * confirms the existing cert is still valid. */
            bool enrollment_succeeded = (rc == ESP_OK && cert_present);
            if (enrollment_succeeded) {
                enterprise_attempts = 0;
            }
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
    esp_err_t init_err = wifi_smart_init_common(&inst_wifi, &inst_ip);
    if (init_err != ESP_OK) {
        ESP_LOGE(TAG, "[b+] wifi_smart_init_common failed: %s",
                 esp_err_to_name(init_err));
        return init_err;
    }

    /* 5. Embedded certs sanity-check.  Cert is always "present" and treated as
     *    non-expired (we cannot evaluate NotAfter without a synced clock and
     *    without parsing the cert -- NTP bootstrap is the mechanism for that). */
    {
        size_t ca_len  = (size_t)(eap_ca_pem_end  - eap_ca_pem_start);
        size_t crt_len = (size_t)(eap_client_crt_end - eap_client_crt_start);
        size_t key_len = (size_t)(eap_client_key_end - eap_client_key_start);
        if (ca_len < EAP_CA_MIN_BYTES) {
            ESP_LOGE(TAG, "EAP cert blob too small: ca.pem got %u need %u",
                     (unsigned)ca_len, (unsigned)EAP_CA_MIN_BYTES);
            return ESP_ERR_INVALID_SIZE;
        }
        if (crt_len < EAP_CRT_MIN_BYTES) {
            ESP_LOGE(TAG, "EAP cert blob too small: client.crt got %u need %u",
                     (unsigned)crt_len, (unsigned)EAP_CRT_MIN_BYTES);
            return ESP_ERR_INVALID_SIZE;
        }
        if (key_len < EAP_KEY_MIN_BYTES) {
            ESP_LOGE(TAG, "EAP cert blob too small: client.key got %u need %u",
                     (unsigned)key_len, (unsigned)EAP_KEY_MIN_BYTES);
            return ESP_ERR_INVALID_SIZE;
        }
    }

    const bool cert_present  = true;
    /* cert_expired is re-evaluated after every NTP sync via the helper
     * eval_embedded_client_cert_expired() (defined below).  Until the
     * clock is plausible we cannot evaluate it, so it starts false. */
    bool cert_expired  = false;

    /* 6. Evaluate clock. */
    time_t now = time(NULL);
    bool ntp_synced = (now >= MIN_PLAUSIBLE_EPOCH);
    if (ntp_synced) {
        cert_expired = eval_embedded_client_cert_expired(now);
    }

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
            if (ntp_synced) {
                cert_expired = eval_embedded_client_cert_expired(now);
                if (cert_expired) {
                    /* Embedded cert is past its notAfter -- the next
                     * enterprise attempt will deterministically fail.
                     * Mode B+ has no re-enrollment path, so log clearly
                     * and slow down (10 min between attempts) so we
                     * still recover if the RADIUS clock gets re-synced. */
                    ESP_LOGE(TAG, "[b+] embedded client.crt is EXPIRED -- "
                                  "EAP-TLS will fail; sleeping 10 min "
                                  "before retrying");
                    vTaskDelay(pdMS_TO_TICKS(600000));
                }
            }
            continue;
        }
    }

    /* Unreachable. */
    return ESP_FAIL;
}
#endif /* WIFI_USE_ENTERPRISE -- end of wifi_init_enterprise_bootstrap (Mode B+) */

#endif /* WIFI_ENTERPRISE_SSID */
