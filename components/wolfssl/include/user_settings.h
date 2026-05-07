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

/* ── ESP32 hardware acceleration ───────────────────────────────── */
/* Disable ESP32 HW crypto — esp32_aes.c / esp32_sha.c use classic ESP32 HAL
 * headers (hal/clk_gate_ll.h, PERIPH_AES_MODULE) absent on ESP32-S3.
 * NO_WOLFSSL_ESP32_CRYPT_HASH disables all SHA HW paths in sha*.c. */
#define NO_WOLFSSL_ESP32_CRYPT_HASH
#define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
#define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA256
#define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA384
#define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA512
#define NO_WOLFSSL_ESP32_CRYPT_AES
