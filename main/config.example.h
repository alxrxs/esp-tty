// MAKE-OTA-IP: 192.168.1.42
// MAKE-FLASH-HOST: user@host.example
/*
 * Marker lines read by the Makefile.
 *
 *   MAKE-OTA-IP   -- target for `make ota <devname>`.  Set to the
 *                    device's IP or hostname on its production network.
 *                    Required by `make ota`; the marker MUST be on the
 *                    first line for legibility but the parser only
 *                    requires the prefix `// MAKE-OTA-IP:`.
 *
 *   MAKE-FLASH-HOST -- target for `make flash-online <devname>`.  Set
 *                    to an SSH-reachable host (e.g. `pi@server.lan`)
 *                    that owns the device's USB cable.  Optional: omit
 *                    if this device is only ever flashed locally, or
 *                    override on the command line with
 *                    `make flash-online <dev> FLASH_HOST=user@host`.
 *
 * Either marker can be commented out and re-added later without
 * affecting the other.
 */

/*
 * config.example.h -- compile-time configuration template for esp-tty
 *
 * Copy this file to config.<devname>.h and edit. The Makefile manages a
 * symlink main/config.h -> config.<devname>.h when you run
 * `make flash <devname>` or `make ota <devname>`. config.h itself is
 * gitignored; the per-device files live alongside it.
 *
 * Every macro below is guarded with #ifndef inside the firmware, so
 * omitting any of them keeps a sensible default.
 */

#pragma once

/* ==========================================================================
 * SSH server
 * ========================================================================== */

#define SSH_PORT    22

/* One or more ED25519 authorized keys for the `tty@` user, in OpenSSH
 * format. Consumed verbatim as an array initializer:
 *
 *     static const char *const keys[] = { AUTHORIZED_PUBKEYS };
 *
 * so each entry is a quoted string, comma-separated, no surrounding braces.
 * Each base64 blob must decode to <= 512 bytes (an ED25519 blob is 51).
 * Entry count is capped by MAX_TTY_KEYS (default 8). */
#define AUTHORIZED_PUBKEYS \
    "ssh-ed25519 AAAA...key1 user@host1", \
    "ssh-ed25519 AAAA...key2 user@host2"

/* ED25519 key used to authenticate `ota@<host>` SSH logins for firmware
 * uploads. Same 512-byte blob limit as AUTHORIZED_PUBKEYS. May be the same
 * key as one of the tty keys or a dedicated deployment key. */
#define OTA_AUTHORIZED_PUBKEY  "ssh-ed25519 AAAA..."

/* ==========================================================================
 * Wi-Fi -- pick ONE of the three modes.
 *
 * IEEE 802.11 locks each SSID to one auth mode at the AP, so PSK and
 * EAP-TLS are always separate networks.
 *
 *   Mode A:  one PSK network only.
 *   Mode B:  one EAP-TLS network only; client cert + key embedded at build.
 *   Mode B+: like Mode B but with a PSK bootstrap network for NTP sync
 *            before EAP-TLS; opt-in via WIFI_ENTERPRISE_SSID.
 *   Mode C:  PSK bootstrap network + EAP-TLS enterprise network, with the
 *            enterprise client cert auto-enrolled via SCEP on first boot
 *            and renewed in the background before expiry.
 * ========================================================================== */

/* -- Mode A: WPA2/WPA3-Personal (PSK) ------------------------------------- *
 * Fill in WIFI_SSID + WIFI_PASS. Do NOT define WIFI_USE_ENTERPRISE or
 * WIFI_ENTERPRISE_SSID.
 *
 * WIFI_SSID: max 32 bytes (wifi_sta_config_t.ssid[32]).
 * WIFI_PASS: 8..63 bytes (WPA2/WPA3-PSK).
 * -------------------------------------------------------------------------- */
#define WIFI_SSID   "your-ssid-here"
#define WIFI_PASS   "your-password-here"

/* -- Mode B: WPA2/WPA3-Enterprise (EAP-TLS), embedded certs --------------- *
 * One network. Place ca.pem / client.crt / client.key in main/certs/ (see
 * main/certs/README.md); the build embeds them via EMBED_TXTFILES.
 *
 * Define WIFI_USE_ENTERPRISE and reassign WIFI_SSID to the enterprise
 * network name. WIFI_PASS is unused in EAP-TLS mode but kept defined for
 * API symmetry.
 *
 * EAP_IDENTITY is the inner identity used after the TLS tunnel is up
 * (in EAP-TLS this is the cert-subject identity).  Max 127 bytes.
 *
 * EAP_ANONYMOUS_IDENTITY (optional, RECOMMENDED for production):
 * Outer identity sent in cleartext during EAP phase 1.  When defined,
 * the device calls esp_eap_client_set_anonymous_identity() so the real
 * EAP_IDENTITY is only exposed inside the TLS tunnel.  Use e.g.
 * "anonymous@your-realm" -- NAI-realm routing on the RADIUS side works
 * off this field.  Without it, EAP_IDENTITY leaks during phase 1.
 *
 * EAP_DISABLE_TIME_CHECK: set to 1 ONLY if the device has no clock and
 * cert-expiry validation is failing at boot. Removes a security check;
 * prefer NTP_ENABLE or Mode B+ / Mode C with NTP_BEFORE_EAPTLS.
 * -------------------------------------------------------------------------- */
/*
#define WIFI_USE_ENTERPRISE
#undef  WIFI_SSID
#undef  WIFI_PASS
#define WIFI_SSID               "your-enterprise-ssid"
#define WIFI_PASS               ""
#define EAP_IDENTITY            "device-cn@example.org"
/* Recommended for production: outer identity sent in cleartext (phase 1). */
#define EAP_ANONYMOUS_IDENTITY  "anonymous@example.org"
#define EAP_DISABLE_TIME_CHECK  1
*/

/* -- Mode B+: EAP-TLS with embedded certs + PSK bootstrap for NTP --------- *
 * Like Mode B, but add WIFI_ENTERPRISE_SSID to enable a two-phase boot:
 *   1. Join WIFI_SSID (PSK) to sync NTP.
 *   2. Join WIFI_ENTERPRISE_SSID (EAP-TLS) with synced clock.
 *
 * Use this when the EAP-TLS AP's RADIUS server validates cert NotBefore/After
 * and the device may have a stale RTC on a cold boot. No SCEP; certs are
 * still build-embedded from main/certs/.
 *
 * NTP_BEFORE_EAPTLS defaults to 1 when NTP_ENABLE is defined; override to
 * 0 if you want to skip the NTP bootstrap even in Mode B+.
 * -------------------------------------------------------------------------- */
/*
#define WIFI_USE_ENTERPRISE
#undef  WIFI_SSID
#undef  WIFI_PASS
#define WIFI_SSID               "your-psk-bootstrap-ssid"
#define WIFI_PASS               "your-psk-password"
#define WIFI_ENTERPRISE_SSID    "your-enterprise-ssid"
#define EAP_IDENTITY            "anonymous@example.org"
#define NTP_ENABLE
*/

/* -- Mode C: PSK bootstrap + EAP-TLS enterprise with SCEP enrollment ------ *
 * TWO distinct SSIDs. Keep WIFI_SSID/WIFI_PASS pointing at the PSK
 * bootstrap network used for NTP sync and SCEP enrollment, and define
 * WIFI_ENTERPRISE_SSID for the production EAP-TLS network.
 *
 * Defining WIFI_ENTERPRISE_SSID is the opt-in switch -- main calls
 * wifi_init_smart() (lib/wifi_state/) and the state machine picks per
 * boot between ENTERPRISE, BOOTSTRAP_NTP_ONLY, and BOOTSTRAP_FULL.
 *
 * Do NOT define WIFI_USE_ENTERPRISE; the state machine drives enterprise
 * mode at runtime.
 *
 * SCEP_URL must be https://. Max 511 chars. SCEP_CHALLENGE_PASSWORD is
 * the one-time enrollment password from the NDES web UI; max 255 chars
 * (PKCS#9 challengePassword limit). Tested against Microsoft NDES in
 * legacy CryptoAPI/CSP mode (RSA-2048 only).
 *
 * BEST PRACTICE — per-device challenge passwords:
 *   Microsoft NDES challenge passwords are single-use enrollment tokens.
 *   Each device config MUST use its own unique password obtained from
 *   the NDES web UI (/certsrv/mscep/mscep.dll?operation=GetCACaps or the
 *   admin portal). Reusing the same password across multiple device configs
 *   weakens defence in depth: if any one device config file leaks, the
 *   shared token is exposed for re-use against the CA for other devices.
 *
 *   The cert already stored in NVS is not affected by rotating the
 *   challenge password; rotation only matters before the next re-enrollment.
 *   See: https://learn.microsoft.com/en-us/previous-versions/windows/
 *     it-pro/windows-server-2012-R2-and-2012/hh831498(v=ws.11)
 * -------------------------------------------------------------------------- */
/*
#define WIFI_ENTERPRISE_SSID     "your-wpa3-enterprise-ssid"
#define EAP_IDENTITY             "anonymous@example.org"
#define SCEP_URL                 "https://scep.example.com/certsrv/mscep/mscep.dll"
#define SCEP_CHALLENGE_PASSWORD  "replace-with-a-unique-per-device-challenge"
*/

/* Subject DN for the SCEP-issued certificate.
 *
 *   SCEP_CN  -- Common Name.  If unset the CN defaults to
 *               "<DEVICE_HOSTNAME>-<mac_lowercase_hex>" (gives per-device
 *               uniqueness automatically).
 *   SCEP_O   -- Organization        (optional)
 *   SCEP_OU  -- Organizational Unit (optional)
 *   SCEP_C   -- Country, 2-char ISO (optional)
 *
 * NDES legacy CryptoAPI/CSP mode ignores most non-CN attributes by policy,
 * but they are still included in the CSR you submit. */
/*
#define SCEP_CN  "device-cn"
#define SCEP_O   "Example Org"
#define SCEP_OU  "Example Unit"
#define SCEP_C   "US"
*/

/* Mode B+ / Mode C clock handling -- pick ONE (or neither).
 *
 *   NTP_BEFORE_EAPTLS:
 *     Sync NTP on the PSK bootstrap network before attempting EAP-TLS.
 *     Applicable to both Mode B+ and Mode C. Defaults to 1 when NTP_ENABLE
 *     is defined; set to 0 to opt out.
 *
 *   SCEP_NO_NTP_USE_ISSUANCE_TIME:
 *     Mode C only / air-gapped. Every boot re-enrolls a fresh cert and uses
 *     its X.509 NotBefore as the local-clock anchor. cert_renewer is
 *     disabled (each reboot is the renewal). Burns one challenge password and
 *     ~9 s per boot. Do not also define NTP_ENABLE if you want truly offline
 *     operation.
 *
 * Defining BOTH is a compile-time error.
 */
/* #define NTP_BEFORE_EAPTLS               1 */
/* #define SCEP_NO_NTP_USE_ISSUANCE_TIME      */

/* Internal Mode C tuning -- defaults shown in parentheses; all have
 * #ifndef fallbacks in main/wifi.c. */

/* Consecutive EAP-TLS failures before forcing a re-enroll. 0 = unlimited
 * (only cert expiry triggers re-enroll). Default 5. */
/* #define WIFI_ENTERPRISE_RETRY_MAX        5 */

/* Seconds to wait for the EAP-TLS handshake before falling back to
 * bootstrap. Bump for VPN-connected RADIUS. Max 300. */
#define EAPTLS_HANDSHAKE_TIMEOUT_SEC        60

/* Seconds to wait for SNTP during the bootstrap paths. Default 30. */
/* #define BOOTSTRAP_NTP_SYNC_TIMEOUT_SEC   30 */

/* Stored cert is treated as expired when fewer than this many seconds
 * remain to NotAfter. Default 86400 (24 h). */
/* #define CERT_REENROLL_THRESHOLD_SEC      86400 */

/* ==========================================================================
 * Certificate renewal watchdog (Mode C only)
 *
 * Available only when WIFI_ENTERPRISE_SSID is defined; cert_renewer_start()
 * runs after wifi_init_smart() returns. Disabled when
 * SCEP_NO_NTP_USE_ISSUANCE_TIME is set.
 * ========================================================================== */

/* Start renewing when fewer than this many days remain to expiry.
 * NDES typically issues 30-day certs; 7 days leaves slack for retries.
 * Range: 1..365. */
#define CERT_RENEWAL_WINDOW_DAYS            7

/* How often the renewer task wakes to check expiry. Range: 60..604800. */
#define CERT_RENEWAL_CHECK_INTERVAL_SEC     86400

/* Retry interval after a failed SCEP attempt (continues indefinitely).
 * Range: 60..86400. */
#define CERT_RENEWAL_RETRY_INTERVAL_SEC     3600

/* ==========================================================================
 * Network identity
 * ========================================================================== */

/* DHCP DISCOVER hostname; also the mDNS name if MDNS_ENABLE is set.
 * RFC 952: letters, digits, hyphens; max 32 bytes. */
#define DEVICE_HOSTNAME          "esp-tty"

/* Optional: override the factory-burned Wi-Fi STA MAC.
 *
 * The MAC MUST be locally administered and unicast. In the first byte:
 *   bit 1 (locally administered) MUST be 1
 *   bit 0 (multicast)            MUST be 0
 * Equivalently the low nibble of byte 0 must be 2, 6, A, or E. ESP-IDF
 * rejects any first byte that violates this and logs the constraint.
 *
 * Exactly 6 bytes (uint8_t[6] initializer). Leave commented out to keep
 * the factory MAC. */
/* #define WIFI_MAC_BYTES  { 0x02, 0x12, 0x34, 0x56, 0x78, 0x9A } */

/* ==========================================================================
 * IPv4 addressing
 *
 * Default (USE_STATIC_IPV4 undefined): DHCPv4 with watchdog.
 * Define USE_STATIC_IPV4 for a fixed address on the enterprise/production
 * network; then STATIC_IPV4_ADDRESS, STATIC_IPV4_NETMASK and
 * STATIC_IPV4_GATEWAY are required.
 *
 * Mode B+ / Mode C note: when WIFI_ENTERPRISE_SSID is also defined, the
 * PSK bootstrap phase (WIFI_SSID) uses DHCP by default even if
 * USE_STATIC_IPV4 is set.  The static address is applied only when joining
 * the enterprise network.  See USE_STATIC_IPV4_BOOTSTRAP below if the
 * bootstrap network also needs a static address.
 * ========================================================================== */
/*
#define USE_STATIC_IPV4
#define STATIC_IPV4_ADDRESS       "10.57.16.91"
#define STATIC_IPV4_NETMASK       "255.255.255.0"
#define STATIC_IPV4_GATEWAY       "10.57.16.1"
#define STATIC_IPV4_DNS_PRIMARY   "1.1.1.1"
#define STATIC_IPV4_DNS_SECONDARY "1.0.0.1"
*/

/* ==========================================================================
 * Bootstrap-network static IPv4 addressing (Mode B+ / Mode C only)
 *
 * Optional.  Requires WIFI_ENTERPRISE_SSID and USE_STATIC_IPV4.
 *
 * When defined, the PSK bootstrap network (the one used during PSK
 * bootstrap for NTP sync / SCEP enrollment, identified by WIFI_SSID)
 * receives a static IP address instead of DHCP.  Use this when the
 * bootstrap network is on a different subnet, VLAN, or simply has no
 * DHCP server.
 *
 * BOOTSTRAP_STATIC_IPV4_ADDRESS, _NETMASK, _GATEWAY are required.
 * DNS servers are optional.
 *
 * When USE_STATIC_IPV4_BOOTSTRAP is not defined (the default), the
 * bootstrap network continues to use DHCP as before.
 * ========================================================================== */
/*
#define USE_STATIC_IPV4_BOOTSTRAP
#define BOOTSTRAP_STATIC_IPV4_ADDRESS       "10.254.1.91"
#define BOOTSTRAP_STATIC_IPV4_NETMASK       "255.255.255.0"
#define BOOTSTRAP_STATIC_IPV4_GATEWAY       "10.254.1.1"
#define BOOTSTRAP_STATIC_IPV4_DNS_PRIMARY   "10.254.1.1"
#define BOOTSTRAP_STATIC_IPV4_DNS_SECONDARY "1.1.1.1"
*/

/* ==========================================================================
 * IPv6 addressing
 *
 * IPV6_MODE selects runtime behaviour. Available values:
 *
 *   IPV6_MODE_DISABLED                no IPv6
 *   IPV6_MODE_SLAAC                   link-local + SLAAC global (default)
 *   IPV6_MODE_SLAAC_STATELESS_DHCPV6  SLAAC address + DHCPv6 for DNS
 *   IPV6_MODE_STATEFUL_DHCPV6         DHCPv6 assigns address + options
 *   IPV6_MODE_STATIC                  fixed global address
 *
 * STATIC_IPV6_ADDRESS / STATIC_IPV6_GATEWAY: max 39 chars.
 * STATIC_IPV6_PREFIX_LEN: 0..128.
 *
 * To compile out IPv6 entirely, also set CONFIG_LWIP_IPV6=n in
 * sdkconfig.defaults.
 * ========================================================================== */
/*
#define IPV6_MODE                 IPV6_MODE_STATIC
#define STATIC_IPV6_ADDRESS       "2001:db8::dead:beef"
#define STATIC_IPV6_PREFIX_LEN    64
#define STATIC_IPV6_GATEWAY       "fe80::1"
#define STATIC_IPV6_DNS_PRIMARY   "2606:4700:4700::1111"
#define STATIC_IPV6_DNS_SECONDARY "2001:4860:4860::8888"
*/

/* ==========================================================================
 * Bootstrap-network IPv6 addressing (Mode B+ / Mode C only)
 *
 * Optional.  Only meaningful when USE_STATIC_IPV4_BOOTSTRAP is defined.
 *
 * BOOTSTRAP_IPV6_MODE selects the IPv6 mode applied to the PSK bootstrap
 * network.  Accepts the same values as IPV6_MODE.  Defaults to
 * IPV6_MODE_DISABLED when not set -- static IPv6 addressing belongs to the
 * enterprise interface, not the transient bootstrap VLAN.
 *
 * When set to IPV6_MODE_STATIC, the BOOTSTRAP_STATIC_IPV6_* macros are
 * required (ADDRESS, PREFIX_LEN, GATEWAY).  DNS servers are optional.
 * ========================================================================== */
/*
#define BOOTSTRAP_IPV6_MODE                 IPV6_MODE_STATIC
#define BOOTSTRAP_STATIC_IPV6_ADDRESS       "2001:db8:1::91"
#define BOOTSTRAP_STATIC_IPV6_PREFIX_LEN    64
#define BOOTSTRAP_STATIC_IPV6_GATEWAY       "fe80::1"
#define BOOTSTRAP_STATIC_IPV6_DNS_PRIMARY   "2606:4700:4700::1111"
#define BOOTSTRAP_STATIC_IPV6_DNS_SECONDARY "2001:4860:4860::8888"
*/

/* ==========================================================================
 * NTP / SNTP
 *
 * Off by default. Define NTP_ENABLE to activate the SNTP client.
 * Required by Mode B when EAP_DISABLE_TIME_CHECK is not set, and by
 * Mode C when NTP_BEFORE_EAPTLS is set.
 * ========================================================================== */
/*
#define NTP_ENABLE
#define NTP_SERVERS           "pool.ntp.org", "time.cloudflare.com"
#define NTP_TIMEZONE          "UTC0"
#define NTP_SYNC_TIMEOUT_SEC  30
*/

/* NTP_SERVERS is consumed as an array initializer; raise
 * CONFIG_LWIP_SNTP_MAX_SERVERS in sdkconfig.defaults if you want more
 * than one entry. NTP_TIMEZONE is a POSIX TZ string; max 64 chars.
 * NTP_SYNC_TIMEOUT_SEC only controls log verbosity during the initial
 * connect window; the client keeps running afterwards. */

/* ==========================================================================
 * UDP log mirror (lib/udp_log/)
 *
 * When both macros are defined, every ESP_LOG* line is mirrored as a UDP
 * datagram to the specified host/port in addition to the normal UART0
 * output.  Useful on the Zero, which lacks the CH340 UART bridge, or any
 * time tailing the serial console is inconvenient.
 *
 * Capture on a Linux/macOS laptop with:
 *   nc -ul 5514
 *
 * UDP_LOG_HOST: destination IPv4 address (dotted-decimal string, required).
 * UDP_LOG_PORT: destination UDP port (integer, required).
 *
 * Log lines produced before Wi-Fi gets an IP are never sent via UDP --
 * they appear only on UART0.  After udp_log_init() is called (triggered
 * automatically by the IP_EVENT_STA_GOT_IP event handler) all subsequent
 * ESP_LOG* calls are mirrored.  Best-effort: if Wi-Fi drops, datagrams
 * are silently discarded and UART0 output is unaffected.
 *
 * ANSI colour escape codes are forwarded verbatim.
 *
 * Datagrams are coalesced up to a near-MTU buffer and prefixed with a
 * "#<seq>\n" header so gaps in the receiver's sequence make lost packets
 * obvious.  Optional tunables (all have sensible defaults):
 *
 *   UDP_LOG_LINE_MAX         per-line scratch buffer        (default 256)
 *   UDP_LOG_DGRAM_MAX        accumulator size in bytes      (default 1300)
 *   UDP_LOG_FLUSH_TIMEOUT_MS idle-flush threshold           (default 50)
 *   UDP_LOG_POLL_MS          flush task tick                (default 25)
 *   UDP_LOG_FLUSH_STACK      flush task stack bytes         (default 4096)
 *   UDP_LOG_FLUSH_PRIO       flush task FreeRTOS priority   (default 3)
 * ========================================================================== */
/*
#define UDP_LOG_HOST  "10.57.16.10"
#define UDP_LOG_PORT  5514
*/

/* ==========================================================================
 * mDNS / Bonjour
 *
 * Off by default. Define MDNS_ENABLE to announce <DEVICE_HOSTNAME>.local
 * and advertise the SSH service on _ssh._tcp.
 * ========================================================================== */
/* #define MDNS_ENABLE  1 */

/* ==========================================================================
 * Wi-Fi country code + TX power (optional)
 *
 * WIFI_COUNTRY_CODE: 2-char ISO country code.  ESP-IDF defaults to "01"
 *   (world domain, channels 1-11).  If your AP runs on channel 12 or 13
 *   you MUST set this explicitly so the chip's RF state machine is fully
 *   initialised for those channels at boot; otherwise the chip can
 *   associate (via passive scan) but trip an internal WiFi crash on the
 *   first burst of TCP traffic.  Examples: "US" (1-11), "DE"/"RO"/"KR"
 *   (1-13), "JP" (1-14).  Calls esp_wifi_set_country_code(..., true), so
 *   ieee80211d is enabled and the AP's beacon can refine the choice.
 *
 * WIFI_MAX_TX_POWER: cap WiFi TX power, in units of 0.25 dBm.  Useful on
 *   boards with a small onboard ceramic antenna (e.g. ESP32-S3-Zero)
 *   where 21 dBm output can RF-couple back into the chip.  Common values:
 *   84 = 21 dBm (chip default), 56 = 14 dBm, 40 = 10 dBm.
 * ========================================================================== */
/* #define WIFI_COUNTRY_CODE  "DE" */
/* #define WIFI_MAX_TX_POWER  56   */

/* ==========================================================================
 * Debug-console mode (USB_DEBUG_CONSOLE_ONLY)
 *
 * IMPORTANT: defining this macro here does nothing on its own.  You MUST
 * also use the matching PlatformIO env (esp32s3_debug or esp32s3_zero_debug)
 * which applies the sdkconfig.debug_console.defaults overlay.  That overlay
 * sets CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y and disables CONFIG_TINYUSB_CDC_ENABLED.
 * Without those sdkconfig changes, the USB-OTG peripheral still starts up and
 * claims GPIO19/20, preventing the USB-Serial-JTAG controller from working.
 *
 * Use the Makefile wrappers instead of defining this macro by hand:
 *   make flash <devname> s3debug        # DevKitC-1 with debug-console
 *   make flash <devname> s3zerodebug    # Zero with debug-console (recommended)
 *   make ota   <devname> s3zerodebug    # OTA to a running debug-console build
 *
 * What it does:
 *   - Skips usb_cdc_init() and the USB TX pump task
 *   - USB-OTG peripheral is never initialised
 *   - USB-Serial-JTAG controller claims GPIO19/20 (shared physical pins)
 *   - ESP_LOG* output streams from the USB-C port as a 303a:1001 CDC ACM device
 *   - Read with: pio device monitor  /  picocom  /  screen  /  cu
 *   - Wi-Fi, SSH (TCP 22), OTA, SCEP, mDNS all remain functional
 *
 * When to use it:
 *   On the Zero, which has no CH340 USB-UART bridge and no UART0 accessible
 *   without an external dongle, this is the easiest way to see the boot log.
 *   Prefer the production env (esp32s3_zero) once bring-up is complete.
 *
 * Defining this macro in config.h has NO EFFECT unless you select the
 * matching _debug PlatformIO env, because the sdkconfig knobs that enable
 * USB-Serial-JTAG console and disable TinyUSB are baked in at configure time.
 * ========================================================================== */
/* #define USB_DEBUG_CONSOLE_ONLY  1 */

/* ==========================================================================
 * USB CDC descriptors
 *
 * VID/PID are reported by lsusb / Windows driver matching; Linux and
 * macOS match CDC ACM devices by class, not VID/PID, so changes here
 * only affect display. The defaults below use Espressif's VID and a
 * development PID; for a published or commercial product, request a
 * proper VID/PID allocation (pid.codes for open hardware, USB-IF for
 * commercial).
 *
 * Each string is converted ASCII -> UTF-16LE by esp_tinyusb and capped
 * at 31 characters.
 *
 * Note: these descriptors are unused in USB_DEBUG_CONSOLE_ONLY builds since
 * TinyUSB is not initialised.
 * ========================================================================== */
#define USB_VID                  0x303a   /* Espressif Systems */
#define USB_PID                  0x4001   /* TinyUSB default CDC */
#define USB_DEVICE_VERSION       0x0100   /* bcdDevice 1.0.0 */
#define USB_MANUFACTURER_STRING  "Your Company"
#define USB_PRODUCT_STRING       "Your Product"
#define USB_SERIAL_STRING        "SN-00000001"
#define USB_CDC_STRING           "Your Product CDC"

/* ==========================================================================
 * Operational tuning -- defaults are production-tuned; override sparingly.
 * ========================================================================== */

/* Max consecutive Wi-Fi reconnect attempts before wifi_init_sta() returns
 * ESP_FAIL. The event handler keeps retrying forever regardless.
 *   0 = unlimited, no failure ever signalled (suits unattended deployments).
 *   N > 0 = signal failure after N tries (tabletop dev). */
#define WIFI_MAX_RETRY              0

/* DHCP watchdog timeout (seconds). Armed when Wi-Fi associates; if no IP
 * arrives within the window, the DHCP client is restarted and the timer
 * re-armed. Set to 0 to disable. */
#define DHCP_RETRY_TIMEOUT_SEC      30

/* Max number of ED25519 hashes stored for AUTHORIZED_PUBKEYS. Each slot
 * is a 32-byte SHA-256 hash in .bss. Range: practical limit ~64. */
#define MAX_TTY_KEYS                8

/* SSH handshake + auth timeout (seconds). A client that does not finish
 * authenticating within the window is dropped. */
#define SSH_HANDSHAKE_TIMEOUT_SEC   30

/* TCP keepalive on the SSH socket (RFC 1122). Defaults detect a dead
 * peer in about 90 s. Bump IDLE for cellular paths (e.g. 600/60/3). */
#define TCP_KEEPALIVE_IDLE_SEC      60
#define TCP_KEEPALIVE_INTVL_SEC     10
#define TCP_KEEPALIVE_COUNT         3

/* SSH-protocol-level keepalive (SSH_MSG_GLOBAL_REQUEST keepalive@openssh.com).
 * Defeats NAT timeouts that drop the TCP connection between TCP
 * keepalive probes. INTERVAL_SEC=0 disables it (TCP keepalive remains). */
#define SSH_KEEPALIVE_INTERVAL_SEC  30
#define SSH_KEEPALIVE_COUNT_MAX     3

/* Seconds the new firmware has to mark itself valid before the
 * bootloader rolls back. Counted from app_main(). Max ~49 days. */
#define OTA_ROLLBACK_DELAY_MS       30000

/* ==========================================================================
 * Memory sizing (PSRAM-backed) -- raise only if you have a concrete need.
 * ========================================================================== */

/* Per-direction ring buffer between SSH and USB CDC. 16 KB handles
 * bursty workloads at 115200 baud with room to spare. */
#define RING_BUFFER_BYTES           (16 * 1024)

/* Scrollback capacity. At 80 cols this is roughly 1600 lines of plain
 * text; less with dense binary output. */
#define SCROLLBACK_BUFFER_BYTES     (128 * 1024)

/* Lines of scrollback replayed when a new SSH client connects. */
#define SCROLLBACK_REPLAY_LINES     1000
