/*
 * config.example.h -- compile-time configuration template for esp-tty
 *
 * Copy this file to config.h, fill in your values, then build.
 * config.h is gitignored and must never be committed.
 */

#pragma once

/* --------------------------------------------------------------------------
 * Wi-Fi -- pick ONE of the three modes below.
 *
 * An IEEE-802.11 SSID is locked to exactly one authentication mode at the
 * AP, so PSK and EAP-TLS are always separate networks.  The three modes
 * below trade off how many networks are involved and when authentication
 * material is provisioned:
 *
 *   Mode A: one PSK network only.
 *   Mode B: one EAP-TLS network only; client cert + key embedded at build.
 *   Mode C: one PSK *bootstrap* network + one EAP-TLS *enterprise* network,
 *           with the enterprise client cert auto-enrolled via SCEP on first
 *           boot (and re-enrolled on expiry).  See the SCEP section near
 *           the bottom of this file for the related knobs.
 * -------------------------------------------------------------------------- */

/* -- Mode A: WPA2/WPA3-Personal (PSK) only -------------------------------- *
 * Fill in WIFI_SSID + WIFI_PASS, do NOT define WIFI_USE_ENTERPRISE or
 * WIFI_ENTERPRISE_SSID.
 * -------------------------------------------------------------------------- */
/* IEEE 802.11 SSID. Max 32 bytes (stored in wifi_sta_config_t.ssid[32]). */
#define WIFI_SSID   "your-ssid-here"
/* WPA passphrase. Range: 8..63 bytes (WPA2/WPA3-PSK spec; IDF stores in
 * wifi_sta_config_t.password[64], so 63 bytes + NUL). */
#define WIFI_PASS   "your-password-here"

/* -- Mode B: WPA2/WPA3-Enterprise (EAP-TLS) only, embedded certs ---------- *
 * One network, EAP-TLS authenticated with a client cert that you placed in
 * main/certs/ at build time.  WIFI_SSID is reassigned to the enterprise
 * network name (the #undef/#redefine pattern below overrides the Mode A
 * value already set above).  WIFI_PASS is kept defined (to empty string)
 * for API symmetry; it is not used in EAP-TLS mode.
 * Uncomment WIFI_USE_ENTERPRISE, do NOT define WIFI_ENTERPRISE_SSID.
 *
 * Place real certs in main/certs/ (see main/certs/README.md) -- the build
 * embeds them via EMBED_TXTFILES.
 *
 * Outer/anonymous EAP identity sent in Phase 1 (before the TLS tunnel is
 * up).  Many RADIUS servers want anonymous@<realm> here; otherwise the
 * cert CN.  Max 127 bytes (esp_eap_client_set_identity limit).

#define WIFI_USE_ENTERPRISE
#undef  WIFI_SSID
#undef  WIFI_PASS
#define WIFI_SSID           "your-enterprise-ssid"
#define WIFI_PASS           ""
#define EAP_IDENTITY        "anonymous@example.org"

 * Optional: set EAP_DISABLE_TIME_CHECK to 1 if the device has no SNTP/RTC
 * and cert expiry validation is failing at boot.
 * WARNING: this removes a security check; enable SNTP in production
 * instead, or use Mode C with OTA_NTP_BEFORE_EAPTLS=1.

#define EAP_DISABLE_TIME_CHECK  1

 * --------------------------------------------------------------------------- *
 *
 * -- Mode C: PSK bootstrap + EAP-TLS enterprise (auto-SCEP enrollment) ----- *
 * TWO separate SSIDs.  Keep WIFI_SSID/WIFI_PASS pointing at your PSK
 * bootstrap network (the one the device joins to sync NTP and run SCEP
 * enrollment).  Then also define WIFI_ENTERPRISE_SSID pointing at the
 * WPA3-Enterprise network the device should use for normal operation.
 *
 * The smart state machine in main/wifi.c (wifi_init_smart) decides at
 * each boot:
 *
 *   ENTERPRISE:       cert in NVS and valid -- go straight to
 *                     WIFI_ENTERPRISE_SSID.
 *   BOOTSTRAP_FULL:   no cert, or cert expired -- join WIFI_SSID (PSK),
 *                     sync NTP, enroll via SCEP against SCEP_URL, reboot
 *                     into WIFI_ENTERPRISE_SSID.
 *   BOOTSTRAP_NTP_ONLY (requires OTA_NTP_BEFORE_EAPTLS=1):
 *                     clock not yet synced -- join WIFI_SSID briefly to
 *                     sync NTP, then loop back for an ENTERPRISE attempt
 *                     (so RADIUS server-cert NotBefore/After can be
 *                     validated).
 *
 * The two SSIDs must be distinct (per 802.11, one SSID = one auth mode).
 * Mode C requires Mode A's WIFI_SSID/WIFI_PASS to be set, plus
 * WIFI_ENTERPRISE_SSID, EAP_IDENTITY, SCEP_URL, and SCEP_CHALLENGE_PASSWORD
 * defined (see the SCEP and Wi-Fi Enterprise sections near the bottom).
 * Do NOT also define WIFI_USE_ENTERPRISE -- the state machine drives
 * enterprise mode at runtime instead.
 * -------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------
 * SSH server
 * -------------------------------------------------------------------------- */
/* TCP port the SSH server listens on. Range: 1..65535 (uint16_t). */
#define SSH_PORT    22

/* One OR MORE authorised public keys in OpenSSH format, comma-separated.
 * This macro is consumed verbatim as the initializer for a C array of strings:
 *
 *     static const char *const keys[] = { AUTHORIZED_PUBKEYS };
 *
 * so each entry must be a quoted string literal, separated by commas, with no
 * surrounding braces. Use a line-continuation backslash on each line except
 * the last. Only ED25519 keys are supported (wolfSSH pubkey auth).
 *
 * Each key string: "ssh-ed25519 <base64> <comment>".  The base64 blob is
 * decoded into a 512-byte staging buffer (pubkey_compute_hash in
 * lib/pubkey_auth/pubkey_auth.c), so the base64 field must decode to at
 * most 512 bytes (~684 base64 chars).  An ED25519 key blob is 51 bytes
 * (68 base64 chars), well within this limit.  The number of entries is
 * bounded by MAX_TTY_KEYS (default 8; only that many hashes are stored).
 *
 * Example with two keys (add or remove entries as needed): */
#define AUTHORIZED_PUBKEYS \
    "ssh-ed25519 AAAA...key1 user@host1", \
    "ssh-ed25519 AAAA...key2 user@host2"

/* OTA update authorised public key -- used when the SSH username is "ota".
 * Can be the same as one of the AUTHORIZED_PUBKEYS or a separate deployment key.
 * This one is still a single string (not a list).
 * Only ED25519 keys are supported.
 *
 * Same blob limit as AUTHORIZED_PUBKEYS: base64 field must decode to at most
 * 512 bytes (~684 base64 chars).
 *
 * Usage: ssh -i <ota-key> ota@<device-ip> < firmware.bin.ota
 */
#define OTA_AUTHORIZED_PUBKEY  "ssh-ed25519 AAAA..."

/* --------------------------------------------------------------------------
 * USB CDC device descriptors
 *
 * All of these values are passed to TinyUSB at runtime (via
 * tinyusb_config_t.descriptor.{device,string}), overriding the Kconfig
 * defaults in sdkconfig.defaults. Edit them here, reflash, done -- no
 * `make menuconfig` needed.
 *
 * IMPORTANT -- about VID / PID:
 *   The defaults are Espressif's VID (0x303a) and the "default TinyUSB CDC"
 *   PID (0x4001). Espressif allows reuse of these on ESP32-S3 chips for
 *   development. They are NOT yours to ship commercially.
 *
 *   For a published open-source project, request a free PID under VID 0x1209
 *   from https://pid.codes -- that's the open-hardware-friendly registry. For
 *   a commercial product, USB-IF assigns vendor IDs for $5,000.
 *
 *   Picking a random VID/PID combo is a USB spec violation and can collide
 *   with future allocations. Don't.
 *
 *   Linux/macOS pick up CDC ACM devices by class, not by VID/PID, so any
 *   change here only affects lsusb display + Windows driver-matching.
 * -------------------------------------------------------------------------- */
/* Vendor ID. Range: 0x0000..0xFFFF (uint16_t). */
#define USB_VID                  0x303a     /* Espressif Systems */
/* Product ID. Range: 0x0000..0xFFFF (uint16_t). */
#define USB_PID                  0x4001     /* TinyUSB default CDC */
/* BCD-encoded device version (e.g. 0x0100 = 1.0.0). Range: 0x0000..0xFFFF (uint16_t BCD). */
#define USB_DEVICE_VERSION       0x0100     /* bcdDevice = 1.0.0 (BCD encoded) */

/* USB string descriptors.
 * The esp_tinyusb wrapper converts ASCII to UTF-16LE and caps each string at
 * MAX_DESC_BUF_SIZE-1 = 31 characters (descriptors_control.c); longer values
 * are silently truncated.  Max 31 characters each. */
#define USB_MANUFACTURER_STRING  "Your Company"
#define USB_PRODUCT_STRING       "Your Product"
#define USB_SERIAL_STRING        "SN-00000001"
#define USB_CDC_STRING           "Your Product CDC"

/* --------------------------------------------------------------------------
 * Network identity
 *
 * Sent as the DHCP DISCOVER hostname, so the device shows up by name in the
 * router's lease table (and is reachable as <hostname>.<local-domain> if the
 * router forwards local DNS).  Keep it short, lowercase, no dots -- RFC 952
 * applies (letters, digits, hyphens; must start with a letter).
 * Max 32 bytes (ESP_NETIF_HOSTNAME_MAX_SIZE in esp_netif_lwip.c; longer values
 * are rejected by esp_netif_set_hostname with an error log).
 * -------------------------------------------------------------------------- */
#define DEVICE_HOSTNAME          "esp-tty"

/* --------------------------------------------------------------------------
 * Network addressing -- IPv4
 *
 * Default (USE_STATIC_IPV4 not defined): DHCPv4.  The DHCP watchdog keeps
 * the client retrying indefinitely; no action required.
 *
 * With USE_STATIC_IPV4 defined: the DHCP client is stopped before the
 * interface comes up and the address below is applied immediately.  The
 * DHCP watchdog timer is disabled automatically.
 *
 * When USE_STATIC_IPV4 is defined, STATIC_IPV4_ADDRESS, STATIC_IPV4_NETMASK,
 * and STATIC_IPV4_GATEWAY are REQUIRED.  DNS entries are optional.
 *
 * USE_STATIC_IPV4: define to enable static IPv4; otherwise undefined (DHCPv4).
 * All IPv4 address strings: max 15 characters ("255.255.255.255").
 *
 * Example:

#define USE_STATIC_IPV4
#define STATIC_IPV4_ADDRESS      "10.57.16.91"
#define STATIC_IPV4_NETMASK      "255.255.255.0"
#define STATIC_IPV4_GATEWAY      "10.57.16.1"
#define STATIC_IPV4_DNS_PRIMARY  "1.1.1.1"       // optional; max 15 characters
#define STATIC_IPV4_DNS_SECONDARY "1.0.0.1"      // optional; max 15 characters

------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------
 * Network addressing -- IPv6
 *
 * sdkconfig.defaults enables CONFIG_LWIP_IPV6=y, CONFIG_LWIP_IPV6_AUTOCONFIG=y,
 * and CONFIG_LWIP_IPV6_DHCP6=y by default.  The mode below selects runtime
 * behaviour.  To compile out IPv6 entirely, set CONFIG_LWIP_IPV6=n in
 * sdkconfig.defaults AND define IPV6_MODE_DISABLED here.
 *
 * Available modes (use the constant name directly):
 *
 *   IPV6_MODE_DISABLED
 *     No IPv6 at all.  esp_netif_create_ip6_linklocal() is never called.
 *
 *   IPV6_MODE_SLAAC  [default when CONFIG_LWIP_IPV6=y]
 *     Stateless Address Autoconfiguration (RFC 4862).  The device derives
 *     a link-local address (fe80::) immediately on L2 association, then
 *     solicits a Router Advertisement to obtain a global /64 prefix.
 *     Requires CONFIG_LWIP_IPV6_AUTOCONFIG=y in sdkconfig.defaults.
 *
 *   IPV6_MODE_SLAAC_STATELESS_DHCPV6
 *     SLAAC for the address (same as above) + stateless DHCPv6 (RFC 3736)
 *     for options such as DNS server addresses.  Useful when the router
 *     doesn't embed DNS in Router Advertisements.
 *     Requires CONFIG_LWIP_IPV6_DHCP6=y in sdkconfig.defaults.
 *
 *   IPV6_MODE_STATEFUL_DHCPV6
 *     DHCPv6 assigns the address and options (RFC 3315).  The router must
 *     advertise the Managed Address Configuration (M) flag.  Most home
 *     routers don't support stateful DHCPv6; primarily useful on enterprise
 *     networks that hand out /128 addresses via DHCPv6.
 *     Requires CONFIG_LWIP_IPV6_DHCP6=y in sdkconfig.defaults.
 *     Note: lwIP's stateful DHCPv6 support is experimental; address
 *     assignment works for basic cases.
 *
 *   IPV6_MODE_STATIC
 *     A fixed global IPv6 address is added immediately on L2 association.
 *     Requires STATIC_IPV6_ADDRESS, STATIC_IPV6_PREFIX_LEN, and
 *     STATIC_IPV6_GATEWAY.  DNS entries are optional.
 *
 * To change the mode, uncomment the desired block below.
 *
 * -- Option 1: SLAAC (default -- no definition needed, shown for clarity) --
 * #define IPV6_MODE  IPV6_MODE_SLAAC
 *
 * -- Option 2: Disable IPv6 entirely --------------------------------------
 * #define IPV6_MODE  IPV6_MODE_DISABLED
 *
 * -- Option 3: SLAAC + stateless DHCPv6 for DNS ---------------------------
 * #define IPV6_MODE  IPV6_MODE_SLAAC_STATELESS_DHCPV6
 *
 * -- Option 4: Stateful DHCPv6 --------------------------------------------
 * #define IPV6_MODE  IPV6_MODE_STATEFUL_DHCPV6
 *
 * -- Option 5: Static IPv6 ------------------------------------------------
 * IPV6_MODE: one of IPV6_MODE_DISABLED, IPV6_MODE_SLAAC,
 *   IPV6_MODE_SLAAC_STATELESS_DHCPV6, IPV6_MODE_STATEFUL_DHCPV6,
 *   IPV6_MODE_STATIC (integer enum values 0..4 defined in wifi.c).
 * STATIC_IPV6_ADDRESS / STATIC_IPV6_GATEWAY: max 39 characters
 *   ("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"); parsed by
 *   esp_netif_str_to_ip6().
 * STATIC_IPV6_PREFIX_LEN: Range: 0..128 (used only in the boot log).
 * DNS strings: same 39-character limit as STATIC_IPV6_ADDRESS.

#define IPV6_MODE               IPV6_MODE_STATIC
#define STATIC_IPV6_ADDRESS     "2001:db8::dead:beef"
#define STATIC_IPV6_PREFIX_LEN  64
#define STATIC_IPV6_GATEWAY     "fe80::1"
#define STATIC_IPV6_DNS_PRIMARY   "2606:4700:4700::1111"   //optional (Cloudflare)
#define STATIC_IPV6_DNS_SECONDARY "2001:4860:4860::8888"   // optional (Google)

 * -------------------------------------------------------------------------- */

/* Optional: override the factory-burned WiFi station MAC address.
 *
 * Each ESP32-S3 has a unique MAC burned at the factory -- by default the
 * firmware uses that.  The active MAC is logged at boot ("WiFi MAC: ...")
 * so you can copy it into a router's static DHCP reservation.
 *
 * Reasons to override:
 *   - swap in a replacement board and keep the same DHCP lease / firewall
 *     rules without reconfiguring upstream
 *   - clone a known identity for testing
 *   - rotate MACs across deployments for privacy
 *
 * CONSTRAINT -- the MAC MUST be locally administered and unicast.
 *
 * In the first byte:
 *   bit 1 (the "locally administered" bit) MUST be 1
 *   bit 0 (the "multicast" bit)            MUST be 0
 *
 * Equivalently, the low nibble of byte 0 must be 2, 6, A, or E.  Valid
 * first bytes (mask 0x03 == 0x02):
 *
 *     02 06 0A 0E
 *     12 16 1A 1E
 *     22 26 2A 2E
 *     32 36 3A 3E
 *     42 46 4A 4E
 *     52 56 5A 5E
 *     62 66 6A 6E
 *     72 76 7A 7E
 *     82 86 8A 8E
 *     92 96 9A 9E
 *     A2 A6 AA AE
 *     B2 B6 BA BE
 *     C2 C6 CA CE
 *     D2 D6 DA DE
 *     E2 E6 EA EE
 *     F2 F6 FA FE
 *
 * INVALID examples that look reasonable but will be REJECTED at boot:
 *   00:11:22:...  (globally-administered range -- assigned to an OUI)
 *   01:...        (multicast bit set)
 *   FF:FF:...     (broadcast)
 *
 * ESP-IDF refuses any first byte outside the table above because this
 * project never burns a custom MAC into eFuse.  Leave the line below
 * commented out to keep the factory MAC; wifi.c will print a clear error
 * naming the constraint if you set an invalid one.
 *
 * Exactly 6 bytes (fixed-size initializer list for uint8_t[6]).
 */
/* #define WIFI_MAC_BYTES  { 0x02, 0x12, 0x34, 0x56, 0x78, 0x9A } */

/* --------------------------------------------------------------------------
 * NTP / SNTP time synchronisation
 *
 * Off by default to keep the firmware off-grid-friendly.
 * Define NTP_ENABLE to activate the SNTP client (uses ESP-IDF esp_netif_sntp
 * API, not the legacy sntp_* macros).
 *
 * NTP_ENABLE: define to enable; otherwise undefined (NTP disabled).

#define NTP_ENABLE

 * NTP_SERVERS: comma-separated list of NTP server hostnames or IP addresses,
 * consumed verbatim as an array initializer:
 *
 *     static const char *const ntp_servers[] = { NTP_SERVERS };
 *
 * Maximum server count: CONFIG_LWIP_SNTP_MAX_SERVERS (default 1; raise to 4
 * in sdkconfig.defaults with CONFIG_LWIP_SNTP_MAX_SERVERS=4).
 * Maximum hostname length: 253 characters (DNS label spec).

#define NTP_SERVERS  "pool.ntp.org", "time.cloudflare.com"

 * NTP_TIMEZONE: POSIX TZ string applied via setenv("TZ",...) + tzset().
 * Examples: "UTC0", "PST8PDT,M3.2.0,M11.1.0", "CET-1CEST,M3.5.0,M10.5.0/3".
 * Max 64 characters (wifi.c truncates at NTP_TZ_MAX_LEN=64 before setenv).

#define NTP_TIMEZONE  "UTC0"

 * NTP_SYNC_TIMEOUT_SEC: how many seconds to log "waiting for NTP sync" at
 * boot before backgrounding.  The SNTP client keeps running after this;
 * the timeout only controls log verbosity during the initial connect window.
 * Default 30. Max practical: 3600.

#define NTP_SYNC_TIMEOUT_SEC  30

 * -------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------
 * mDNS / Bonjour
 *
 * Off by default.  Define MDNS_ENABLE to have the device announce itself as
 * <DEVICE_HOSTNAME>.local on the LAN and advertise the SSH service on
 * _ssh._tcp.  Adds ~5 KB of flash and a small multicast cost.
 */
/* #define MDNS_ENABLE 1 */

/* --------------------------------------------------------------------------
 * Operational tuning -- leave the defaults unless you have a reason
 * -------------------------------------------------------------------------- */

/* Max consecutive Wi-Fi reconnect attempts before wifi_init_sta() returns
 * ESP_FAIL.  After that the event handler keeps retrying forever anyway.
 *
 * 0 (the default) = unlimited retries, NO failure ever signalled.
 * wifi_init_sta() then blocks indefinitely on first boot until an IP is
 * obtained.  Suits off-grid / unattended deployments where the AP may
 * be intermittent and there is no human to consume the failure signal.
 *
 * Set to a positive integer if you'd rather have the device proceed
 * without WiFi after a finite number of failures (e.g. for a tabletop
 * dev workflow where you might want to use the USB side without WiFi).
 * Max practical: 32767 (compared against int s_retry_num in wifi.c). */
#define WIFI_MAX_RETRY              0
/* #define WIFI_MAX_RETRY              10  // tabletop: give up after 10 tries */

/* DHCP watchdog timeout (seconds).  Armed when Wi-Fi associates (L2 link
 * up); fires if no IP is obtained within this window, restarts the DHCP
 * client, and re-arms.  Loops forever until DHCP succeeds.
 *
 * Protects against the case where the AP is up but the DHCP server is
 * stuck -- lwIP gives up DHCP DISCOVER after a few retries on its own,
 * leaving the device IP-less indefinitely.  Set to 0 to disable.
 * Max practical: 3600 (1 hour); the value is multiplied by 1000 for
 * pdMS_TO_TICKS, so values above ~4294967 overflow uint32_t. */
#define DHCP_RETRY_TIMEOUT_SEC      30
/* #define DHCP_RETRY_TIMEOUT_SEC      0   // disable watchdog */

/* Max number of TTY pubkeys that can appear in AUTHORIZED_PUBKEYS.
 * Bump if you have more than 8 admins.
 * Max practical: 64 (each entry uses a 32-byte SHA-256 hash slot in the
 * static s_authkey_hashes array; larger values grow .bss proportionally). */
#define MAX_TTY_KEYS                8

/* SSH handshake + auth timeout (seconds).  A client that does not complete
 * authentication within this window is dropped, freeing the session slot.
 * Stored in struct timeval.tv_sec (long) for SO_RCVTIMEO.
 * Max practical: 3600. */
#define SSH_HANDSHAKE_TIMEOUT_SEC   30

/* TCP keepalive on the SSH socket (RFC 1122 sec 4.2.3.6).
 *   IDLE  = seconds of inactivity before the first probe
 *   INTVL = seconds between subsequent probes
 *   COUNT = unanswered probes before the connection is dropped
 * Defaults detect a dead peer in about 90 s.  Bump IDLE for cellular
 * (e.g. 600 / 60 / 3); lower for fragile LAN paths.
 * IDLE and INTVL: stored as 1000*value in lwIP's u32_t (milliseconds);
 *   max 4294967 seconds before uint32_t overflow.
 * COUNT: stored as u32_t probe count; max 4294967295 (use small values). */
#define TCP_KEEPALIVE_IDLE_SEC      60
#define TCP_KEEPALIVE_INTVL_SEC     10
#define TCP_KEEPALIVE_COUNT         3

/* SSH-protocol-level keepalive (application-layer, distinct from TCP keepalive).
 * Sends SSH_MSG_GLOBAL_REQUEST ("keepalive@openssh.com", want-reply=1) after
 * INTERVAL_SEC seconds of pump-loop idleness; drops the session after
 * COUNT_MAX unanswered probes.  Mirrors OpenSSH ClientAliveInterval /
 * ClientAliveCountMax semantics.  Defeats NAT timeouts that drop the TCP
 * connection between TCP keepalive probes.
 *
 * INTERVAL_SEC: seconds of idleness before the first probe.
 *   Set to 0 to disable SSH-level keepalive entirely (TCP keepalive remains).
 *   Stored as pdMS_TO_TICKS(SSH_KEEPALIVE_INTERVAL_SEC * 1000) in
 *   ssh_keepalive_t.interval_ticks (TickType_t / uint32_t); max 4294967
 *   seconds before overflow. Range: 0..3600.
 *
 * COUNT_MAX: unanswered probes before the session is dropped.
 *   Default 3 gives ~90 s detection time with the default 30 s interval,
 *   matching OpenSSH defaults.  Stored in ssh_keepalive_t.count_max (uint32_t).
 *   Range: 1..1000. */
#define SSH_KEEPALIVE_INTERVAL_SEC  30
#define SSH_KEEPALIVE_COUNT_MAX     3

/* How long the new firmware has to prove itself before the bootloader
 * rolls back.  Starts ticking at app_main(); the SSH server marks the
 * image valid this many ms after boot.
 * Passed to pdMS_TO_TICKS (TickType_t / uint32_t); max 4294967295 ms
 * (~49 days) before overflow. Max practical: 300000 (5 minutes). */
#define OTA_ROLLBACK_DELAY_MS       30000

/* --------------------------------------------------------------------------
 * Memory sizing (PSRAM-backed) -- increase only if you have a concrete need
 * -------------------------------------------------------------------------- */

/* Per-direction ring buffer between SSH and USB CDC.  16 KB handles
 * bursty workloads at 115200 baud with room to spare.
 * Allocated from PSRAM via heap_caps_malloc. Max practical: 4 MB
 * (two rings are allocated; leave headroom for scrollback and heap). */
#define RING_BUFFER_BYTES           (16 * 1024)

/* Scrollback capacity: total bytes retained.  At 80 cols this is roughly
 * 1600 lines of plain text; higher with shorter lines, lower with binary
 * output.  Increase if your target produces dense log bursts.
 * Allocated from PSRAM. Max practical: 4 MB (ESP32-S3-N16R8 has 8 MB
 * PSRAM; leave headroom for ring buffers and heap). */
#define SCROLLBACK_BUFFER_BYTES     (128 * 1024)

/* Number of lines of scrollback to replay when a new SSH client connects.
 * Lower this if the connect-time scrollback feels noisy.
 * Passed as int max_lines to scrollback_get_lines(); max INT_MAX
 * (2147483647), though practically bounded by SCROLLBACK_BUFFER_BYTES. */
#define SCROLLBACK_REPLAY_LINES     1000

/* --------------------------------------------------------------------------
 * Wi-Fi Enterprise + SCEP auto-enrollment  (Mode C from the top of file)
 *
 * Defining WIFI_ENTERPRISE_SSID is the opt-in switch for Mode C: it makes
 * app_main() call wifi_init_smart() instead of the legacy wifi_init_sta().
 * The state machine then has TWO networks to choose between at each boot:
 *
 *     WIFI_SSID + WIFI_PASS          -- PSK bootstrap (set in Mode A block above)
 *     WIFI_ENTERPRISE_SSID + EAP_*   -- WPA3-Enterprise (this block)
 *
 * These MUST be two different SSIDs.  A single AP-side SSID can only carry
 * one auth mode (PSK or 802.1X), so the bootstrap PSK network and the
 * production EAP-TLS network are physically separate networks (typically
 * separate VLANs on the same access point).
 *
 * Per-boot decision (see lib/wifi_state/):
 *
 *   1. Read the NVS credential store (lib/cred_store/).
 *   2. Decide one of: ENTERPRISE, BOOTSTRAP_NTP_ONLY, BOOTSTRAP_FULL.
 *   3. ENTERPRISE: join WIFI_ENTERPRISE_SSID via EAP-TLS using the cert
 *      from NVS.  Normal operating mode.
 *   4. BOOTSTRAP_NTP_ONLY: join WIFI_SSID (PSK), sync NTP, drop, loop back
 *      to step 2.  Used when OTA_NTP_BEFORE_EAPTLS is set and the clock
 *      is unsynced (needed so RADIUS server-cert NotBefore/After can be
 *      validated on the next ENTERPRISE attempt).
 *   5. BOOTSTRAP_FULL: join WIFI_SSID (PSK), sync NTP, run SCEP enrollment
 *      against SCEP_URL / SCEP_CHALLENGE_PASSWORD, store cert in NVS,
 *      reboot into ENTERPRISE.
 *
 * When WIFI_ENTERPRISE_SSID is NOT defined the smart state machine is
 * compiled out and the build falls back to Modes A or B unchanged.
 *
 * SCEP wire details (RFC 8894):
 *   Key algorithm: RSA-2048 SHA-256 PKCS#1v1.5 (§3.5.2).  Microsoft NDES
 *   in legacy CryptoAPI/CSP mode only accepts RSA-signed pkiMessages;
 *   ECDSA returns failInfo=1 (badMessageCheck).  Tested working against
 *   Microsoft NDES.
 *
 * To enable Mode C, uncomment the four defines in the template block below
 * (WIFI_ENTERPRISE_SSID, EAP_IDENTITY, SCEP_URL, SCEP_CHALLENGE_PASSWORD).
 *
 * IEEE 802.11 SSID max: 32 bytes.
 * SCEP_URL max: 511 chars (SCEP_URL_MAX - 1 in scep_transport.c); must use
 *   the https:// scheme (scep_transport.c rejects non-HTTPS URLs before
 *   making any network connection).
 * SCEP_CHALLENGE_PASSWORD max: 255 chars (PKCS#9 challengePassword limit).
 *   Keep confidential -- it authorises certificate issuance.
 * -------------------------------------------------------------------------- */

/* Uncomment the whole block to enable Mode C:

#define WIFI_ENTERPRISE_SSID     "your-wpa3-enterprise-ssid"
#define EAP_IDENTITY             "anonymous@example.org"
#define SCEP_URL                 "https://scep.example.com/certsrv/mscep/mscep.dll"
#define SCEP_CHALLENGE_PASSWORD  "replace-with-your-static-challenge"

 * -------------------------------------------------------------------------- */

/* OTA_NTP_BEFORE_EAPTLS: when defined (set to 1), the Wi-Fi state machine
 * syncs NTP time before starting the EAP-TLS handshake.  This ensures the
 * device clock is correct for certificate validity checks.  Requires
 * NTP_ENABLE to also be defined.
 *
 * MUTUALLY EXCLUSIVE with SCEP_NO_NTP_USE_ISSUANCE_TIME below: the two
 * options are opposite approaches to the unsynced-clock problem.  Defining
 * both produces a compile-time #error.
 *
 * Define to enable (value 1 is conventional but any non-zero value works):
 */
/* #define OTA_NTP_BEFORE_EAPTLS  1 */

/* SCEP_NO_NTP_USE_ISSUANCE_TIME: "no-NTP, fresh-cert-every-boot" mode.
 *
 * Use case: off-grid or air-gapped devices with no reachable NTP source.
 * Instead of syncing the clock via SNTP before joining the enterprise network,
 * the device re-enrolls a fresh SCEP certificate on every boot and uses the
 * issued cert's X.509 NotBefore field as a local-time anchor.  The CA clock
 * is effectively the authoritative time source.
 *
 * How it works:
 *   1. Every boot the state machine takes the BOOTSTRAP_FULL path: joins the
 *      PSK network, runs SCEP enrollment, receives a fresh cert from the CA.
 *   2. The new cert's NotBefore (CA-attested "now") is extracted via
 *      cred_store_parse_not_before() and applied with settimeofday().
 *   3. The device reboots and joins the enterprise network with a fresh cert
 *      and an approximately-correct clock anchor.
 *   4. The cert_renewer background task is skipped -- each reboot is already
 *      a renewal.
 *
 * Trade-offs:
 *   - Every boot incurs a full SCEP enrollment (~9 s round-trip to NDES).
 *   - Each enrollment burns one NDES challenge password and creates one CA
 *     audit-log entry.  High-frequency reboots will exhaust static challenge
 *     pools faster; configure NDES for auto-challenge or set a generous OTP
 *     pool.
 *   - The clock anchor is only as accurate as the CA's clock, minus any
 *     skew introduced by enrollment latency.  For a CA that applies NotBefore
 *     at the moment of signing, accuracy is typically within seconds.  For a
 *     CA that pre-dates certs by minutes (to tolerate clock skew in the
 *     client), the anchor may be slightly in the past -- which is acceptable
 *     for certificate validity checks.
 *   - After the reboot, time(NULL) drifts forward at the normal rate of the
 *     on-chip oscillator.  Without NTP the clock will gradually diverge from
 *     wall time across reboots.  Reboot frequently enough to keep the drift
 *     within the CA's clock-skew tolerance window (typically ±5 minutes for
 *     Kerberos-based RADIUS).
 *   - MUTUALLY EXCLUSIVE with OTA_NTP_BEFORE_EAPTLS.  Defining both is a
 *     compile-time error (wifi.c #errors out).
 *
 * Implied settings when this macro is defined:
 *   - NTP_ENABLE is NOT required (and should not be defined if you want a
 *     truly air-gapped device).
 *   - cert_renewer background task is disabled.
 *   - The per-boot BOOTSTRAP_FULL path always runs, regardless of whether a
 *     valid cert is already stored in NVS.
 */
/* #define SCEP_NO_NTP_USE_ISSUANCE_TIME */

/* EAPTLS_FALLBACK_TIMEOUT_SEC: seconds to wait for the EAP-TLS handshake
 * to complete before falling back (e.g. reverting to PSK or aborting).
 * The Wi-Fi state machine starts this timer when enterprise mode is active
 * and EAP_DISABLE_TIME_CHECK is not set.
 *
 * Lower values catch a stuck RADIUS server faster but may fail on high-
 * latency links (VPN-connected RADIUS, intercontinental enterprise).
 * Default 60 s. Max practical: 300 (5 minutes). */
#define EAPTLS_FALLBACK_TIMEOUT_SEC  60

/* -- Internal Mode-C tunables (defaults usually fine) --------------------- *
 * These all have #ifndef fallbacks in main/wifi.c; override only if you
 * have a specific reason.  Leaving them undefined here uses the defaults
 * shown in parentheses.
 * -------------------------------------------------------------------------- */

/* WIFI_ENTERPRISE_RETRY_MAX: after this many consecutive failed enterprise
 * auth attempts, the state machine assumes the stored cert is bad and
 * falls back to BOOTSTRAP_FULL (re-enrolls) even if NTP says the cert is
 * still valid.  0 = unlimited (never fall back due to attempt count alone;
 * only cert expiry triggers fallback).  Default 5. */
/* #define WIFI_ENTERPRISE_RETRY_MAX        5 */

/* SMART_NTP_SYNC_TIMEOUT_SEC: how long the BOOTSTRAP_NTP_ONLY and
 * BOOTSTRAP_FULL paths wait for SNTP to deliver a synced time before
 * giving up and proceeding (with whatever clock the device has).  Default
 * 30 s.  Bump this if your NTP source is high-latency. */
/* #define SMART_NTP_SYNC_TIMEOUT_SEC       30 */

/* CERT_EXPIRY_WINDOW_SEC: stored cert is treated as "expired" when fewer
 * than this many seconds remain to NotAfter.  Triggers BOOTSTRAP_FULL on
 * the next boot decision.  Default 86400 (24 hours) so an overnight expiry
 * doesn't surprise you.  Bump higher for short-lived (hours-scale) certs. */
/* #define CERT_EXPIRY_WINDOW_SEC           86400 */

/* EAP_IDENTITY note (when WIFI_USE_ENTERPRISE or WIFI_ENTERPRISE_SSID is
 * defined):
 *   When SCEP_URL is also defined (Mode C), the SCEP-issued certificate CN is
 *   used as the EAP-TLS client identity presented to the RADIUS server.  The
 *   outer anonymous identity (EAP_IDENTITY, sent before the TLS tunnel is up)
 *   is still taken from this macro; it is typically "anonymous@<realm>" for
 *   privacy.  The inner identity is derived from the client certificate CN
 *   by the RADIUS server.
 */

/* --------------------------------------------------------------------------
 * Certificate renewal watchdog (cert_renewer.c)
 *
 * Available only when WIFI_ENTERPRISE_SSID is defined (Mode C above).
 * cert_renewer_start() is called by app_main() after wifi_init_smart()
 * returns ESP_OK.  The task polls the stored cert's NotAfter and re-enrolls
 * via SCEP when the cert is within CERT_RENEWAL_WINDOW_DAYS of expiry.
 *
 * Assumption: the SCEP server is reachable from the enterprise segment
 * (corporate routing); no PSK detour is needed for renewal.
 * -------------------------------------------------------------------------- */

/* CERT_RENEWAL_WINDOW_DAYS: start renewing when the stored cert has fewer
 * than this many days remaining.  Cert lifetime from NDES is typically
 * 30 days; a 7-day window leaves slack for retries if SCEP is briefly
 * unreachable.  Range: 1..365. */
#define CERT_RENEWAL_WINDOW_DAYS          7

/* CERT_RENEWAL_CHECK_INTERVAL_SEC: how often the renewer task wakes up
 * to check expiry when no renewal is in progress.  86400 = once per day.
 * Range: 60..604800 (1 minute to 1 week). */
#define CERT_RENEWAL_CHECK_INTERVAL_SEC   86400

/* CERT_RENEWAL_RETRY_INTERVAL_SEC: how often to retry SCEP when a renewal
 * attempt fails.  Continues indefinitely (no giveup).  3600 = once per
 * hour.  Range: 60..86400. */
#define CERT_RENEWAL_RETRY_INTERVAL_SEC   3600
