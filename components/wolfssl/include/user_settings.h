/*
 * wolfssh_options.h — wolfSSH + wolfSSL user settings for esp-tty
 *
 * Included via WOLFSSL_USER_SETTINGS (set in CMakeLists / platformio.ini).
 * Defines the minimum feature set for ED25519 host key + pubkey auth.
 */

#pragma once

/* ── ESP32 platform ─────────────────────────────────────────────── */
#define WOLFSSL_ESPIDF
#define WOLFSSL_ESP32
#ifndef ESP_ENABLE_WOLFSSH
#define ESP_ENABLE_WOLFSSH
#endif
#ifndef WOLFSSL_WOLFSSH
#define WOLFSSL_WOLFSSH
#endif

/* ── wolfSSH features ──────────────────────────────────────────── */
#define WOLFSSH_TEST_SERVER         /* enable server-side API        */
#define WOLFSSH_TERM                /* accept PTY requests           */
#define WOLFSSH_SHELL               /* enable window-change resize callback */
#define DEFAULT_WINDOW_SZ  2000    /* shrunk for embedded use       */

/* ── Crypto: ED25519 only (RSA disabled to save ~40 KB flash) ──── */
#define HAVE_ECC
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_STREAMING_VERIFY   /* required by wolfSSH   */
#define WOLFSSL_SHA512              /* required by ED25519           */
#define USE_FAST_MATH

/* ── Embedded constraints ──────────────────────────────────────── */
#define NO_FILESYSTEM
#define NO_OLD_TLS
#define WOLFSSL_SMALL_STACK
#define NO_RSA
#define WOLFSSH_NO_RSA

/* ── wolfSSH cipher hardening ──────────────────────────────────── */
/* AES-GCM is the only cipher we want (AEAD, no padding oracle surface).
 * Explicitly enable it — our minimal config doesn't auto-define HAVE_AESGCM. */
#define HAVE_AESGCM
/* Disable SHA-1 MAC algorithms (hmac-sha1, hmac-sha1-96). */
#define WOLFSSH_NO_HMAC_SHA1
#define WOLFSSH_NO_HMAC_SHA1_96
/* Disable DH key exchange — prefer X25519/ECDH. */
#define WOLFSSH_NO_DH
/* Disable AES-CBC — wolfSSH internal.h auto-sets WOLFSSH_NO_AES_CBC when
 * HAVE_AES_CBC is absent; we declare it explicitly for clarity. */
#define WOLFSSH_NO_AES_CBC
/* Disable AES-192 entirely at the wolfSSL level.
 * Without WOLFSSL_AES_COUNTER defined (we don't need CTR mode), wolfSSH's
 * internal.h already auto-sets WOLFSSH_NO_AES_CTR, removing aes192-ctr and
 * aes256-ctr from cipher negotiation.  NO_AES_192 additionally prevents
 * WOLFSSL_AES_192 from being set in settings.h, stripping any AES-192 key
 * scheduling code from wolfSSL and making aes192-gcm@openssh.com unusable
 * even if a client somehow selects it.  The runtime cipher list is further
 * pinned to "aes256-gcm@openssh.com" only via wolfSSH_CTX_SetAlgoListCipher
 * in ssh_server.c. */
#define NO_AES_192

/* ── ESP32 hardware acceleration ────────────────────────────────── */
/*
 * wolfSSL HW crypto is ENABLED for wolfSSL/wolfSSH operations on ESP32-S3.
 *
 * Platform: PlatformIO espressif32@6.11.0 → ESP-IDF 5.4.1 LTS.
 *
 * esp32_sha.c and esp32_aes.c use the periph_ctrl API which is present in
 * IDF 5.4 LTS.  The components/wolfssl bridge CMakeLists.txt includes both
 * files in the GLOB and adds PRIV_REQUIRES esp_hw_support so the clock-
 * gating symbols resolve at link time.
 *
 * HW-accelerated:
 *   - SHA-256 / SHA-384 / SHA-512  (ESP32-S3 SHA peripheral)
 *   - AES-128-GCM / AES-256-GCM    (ESP32-S3 AES peripheral)
 *
 * AES-192 is NOT compiled (NO_AES_192 above) and NOT offered in SSH cipher
 * negotiation.  The ESP32-S3 AES peripheral only supports 128-bit and 256-bit
 * keys anyway (silicon limitation, wolfSSL GitHub #6375).
 * NO_WOLFSSL_ESP32_CRYPT_AES_192 below is now redundant (no AES-192 code is
 * compiled at all) but kept to guard against any future partial re-enablement.
 *
 * OTA operations (mbedTLS) continue to use HW via CONFIG_MBEDTLS_HARDWARE_AES/SHA.
 */
#define NO_WOLFSSL_ESP32_CRYPT_AES_192
