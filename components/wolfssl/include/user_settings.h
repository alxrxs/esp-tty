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

/* Strip the wolfSSL TLS 1.2/1.3 record layer and handshake state machine
 * entirely.  We only use wolfSSL as wolfSSH's crypto provider (AES-GCM,
 * ED25519, SHA-512, HKDF) -- the TLS code paths are dead weight and
 * extra attack surface.  All HTTPS/EAP-TLS in this firmware goes through
 * mbedTLS, not wolfSSL.  See M5. */
#define NO_TLS
#define WOLFCRYPT_ONLY

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
 * wolfSSL HW crypto is ENABLED for wolfSSL/wolfSSH operations on ESP32-S3.
 *
 * patches/wolfssl__wolfssl/0002-adapt-esp32-aes-sha-to-idf6-periph-clock-api.patch
 * adapted esp32_aes.c and esp32_sha.c to the IDF 6.0 HAL API:
 *   - periph_module_enable/disable(PERIPH_AES_MODULE) replaced by
 *     esp_crypto_aes_enable_periph_clk(true/false)
 *   - periph_module_enable/disable(PERIPH_SHA_MODULE) replaced by
 *     esp_crypto_sha_enable_periph_clk(true/false)
 *   - #include <hal/clk_gate_ll.h> replaced by esp_crypto_periph_clk.h
 *
 * Both files are now compiled (no longer excluded in CMakeLists.txt).
 * WOLFSSL_ESP32_CRYPT is set implicitly when neither NO_ESP32_CRYPT nor
 * NO_WOLFSSL_ESP32_CRYPT_AES / NO_WOLFSSL_ESP32_CRYPT_HASH are defined.
 *
 * AES-256-GCM (SSH data cipher) and SHA-512 (ED25519) offload to the
 * ESP32-S3 crypto accelerator, reducing CPU load on the SSH bridge path.
 * OTA/TLS operations continue to use hardware acceleration via mbedTLS
 * (CONFIG_MBEDTLS_HARDWARE_AES=y / CONFIG_MBEDTLS_HARDWARE_SHA=y).
 */
