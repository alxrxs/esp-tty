/*
 * wolfssh_options.h -- wolfSSH + wolfSSL user settings for esp-tty
 *
 * Included via WOLFSSL_USER_SETTINGS (set in CMakeLists / platformio.ini).
 * Defines the minimum feature set for ED25519 host key + pubkey auth.
 */

#pragma once

/* -- ESP32 platform ----------------------------------------------- */
#define WOLFSSL_ESPIDF
#define WOLFSSL_ESP32
#ifndef ESP_ENABLE_WOLFSSH
#define ESP_ENABLE_WOLFSSH
#endif
#ifndef WOLFSSL_WOLFSSH
#define WOLFSSL_WOLFSSH
#endif

/* -- wolfSSH features -------------------------------------------- */
#define WOLFSSH_TEST_SERVER         /* enable server-side API        */
#define WOLFSSH_TERM                /* accept PTY requests           */
#define WOLFSSH_SHELL               /* enable window-change resize callback */
#define DEFAULT_WINDOW_SZ  2000    /* shrunk for embedded use       */

/* -- Crypto: ED25519 only (SCEP enrollment now uses mbedTLS RSA) -- */
/* RSA is no longer compiled into wolfSSL.  SCEP uses mbedTLS directly,
 * which avoids the wolfSSL PKCS#7/RSA-4096 crash in AddRecipient_KTRI.
 * mbedTLS RSA is always available on ESP32 (it is the OTA/TLS stack). */
#define HAVE_ECC
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_STREAMING_VERIFY   /* required by wolfSSH   */
#define WOLFSSL_SHA512              /* required by ED25519           */
#define USE_FAST_MATH

/* Disable RSA in wolfSSL -- SCEP now uses mbedTLS for all RSA operations */
#define NO_RSA

/* -- Embedded constraints ---------------------------------------- */
#define NO_FILESYSTEM
#define NO_OLD_TLS
#define WOLFSSL_SMALL_STACK

/* -- wolfSSH cipher hardening ------------------------------------ */
/* AES-GCM is the only cipher we want (AEAD, no padding oracle surface).
 * Explicitly enable it -- our minimal config doesn't auto-define HAVE_AESGCM. */
#define HAVE_AESGCM

/* OTA inner key exchange: HKDF-SHA256 derives the per-upload AES-256-GCM
 * key from the X25519 shared secret (see main/ota_session.c).  Needs HMAC,
 * which is enabled by default when NO_HMAC is not set (our config does not
 * define NO_HMAC). */
#define HAVE_HKDF
/* Disable SHA-1 MAC algorithms (hmac-sha1, hmac-sha1-96). */
#define WOLFSSH_NO_HMAC_SHA1
#define WOLFSSH_NO_HMAC_SHA1_96
/* Disable DH key exchange -- prefer X25519/ECDH. */
#define WOLFSSH_NO_DH
/* Disable AES-CBC -- wolfSSH internal.h auto-sets WOLFSSH_NO_AES_CBC when
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

/* -- SCEP wire-protocol: now handled entirely by mbedTLS ----------- */
/* scep_proto.c no longer uses any wc_PKCS7_* or wc_MakeCert* APIs.
 * All PKCS#7 EnvelopedData / SignedData construction and parsing is done
 * with hand-rolled DER writes and mbedtls_aes_* / mbedtls_rsa_* calls.
 * This removes the wolfSSL PKCS#7 code path that crashed on RSA-4096
 * RA certs inside wc_PKCS7_AddRecipient_KTRI. */

/* -- ESP32 hardware acceleration ---------------------------------- */
/*
 * wolfSSL HW crypto is DISABLED for wolfSSL/wolfSSH operations on ESP32-S3.
 *
 * ESP-IDF 6.0.1 removed PERIPH_AES_MODULE / PERIPH_SHA_MODULE and moved
 * hal/clk_gate_ll.h into a new component (esp_hal_clock) that is not in the
 * public include path.  wolfSSL 5.8.2's esp32_aes.c / esp32_sha.c still
 * reference the old IDF 5.x periph_ctrl API and therefore do not compile
 * against IDF 6.0.
 *
 * wolfSSH only uses ED25519 (sign/verify) and AES-256-GCM (SSH data cipher),
 * both of which fall back to wolfSSL's fast software implementations (sp_c64,
 * TI-SHAtransform).  The performance impact is negligible for a serial-bridge
 * workload.
 *
 * OTA and TLS operations continue to use ESP32-S3 hardware acceleration via
 * CONFIG_MBEDTLS_HARDWARE_AES=y / CONFIG_MBEDTLS_HARDWARE_SHA=y (independent
 * of wolfSSL).
 *
 * esp32_aes.c and esp32_sha.c are excluded from the build in
 * components/wolfssl/CMakeLists.txt.
 */
/* NO_ESP32_CRYPT disables hardware acceleration.  However, wolfSSL 5.8.2 has
 * a latent bug in openssl/sha.h: it checks !defined(NO_WOLFSSL_ESP32_CRYPT_HASH)
 * to decide whether WC_ESP32SHA is in scope, but that symbol is only defined
 * inside esp32-crypt.h, which is conditionally included via sha256.h only when
 * WOLFSSL_ESP32_CRYPT is set (which NO_ESP32_CRYPT suppresses).  The net effect
 * is that when NO_ESP32_CRYPT is set, NO_WOLFSSL_ESP32_CRYPT_HASH is never
 * defined in the usual path, so openssl/sha.h still tries to use WC_ESP32SHA.
 * Explicitly defining it here closes that gap. */
#define NO_ESP32_CRYPT
#define NO_WOLFSSL_ESP32_CRYPT_HASH
#define NO_WOLFSSL_ESP32_CRYPT_AES
