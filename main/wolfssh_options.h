/*
 * wolfssh_options.h -- wolfSSH + wolfSSL user settings for esp-tty
 *
 * =====================================================================
 *  STALE / NOT COMPILED -- DO NOT EDIT TO CHANGE BUILD BEHAVIOUR.
 * =====================================================================
 *
 * This file is NOT part of any build.  wolfSSL is configured exclusively
 * through:
 *
 *     components/wolfssl/include/user_settings.h
 *
 * which the wolfssl managed component locates at compile time via
 * -DWOLFSSL_USER_SETTINGS_DIR="<project>/include/user_settings.h"
 * (see managed_components/wolfssl__wolfssl/CMakeLists.txt).  No C source,
 * CMakeLists, or platformio.ini #includes or references THIS file, and the
 * two files have since diverged substantially (the live one additionally
 * sets NO_TLS / WOLFCRYPT_ONLY, HAVE_AESGCM, HAVE_HKDF, NO_AES_192, the
 * wolfSSH cipher-hardening flags, and enables ESP32 HW crypto).
 *
 * It is kept only because main/README.md still references it by name.
 * To change actual crypto settings, edit components/wolfssl/include/
 * user_settings.h -- editing this file has no effect on the firmware.
 *
 * (SSH-F4: verified stale + uncompiled.)
 */

#pragma once

/* -- ESP32 platform ----------------------------------------------- */
#define WOLFSSL_ESPIDF
#define WOLFSSL_ESP32
#define ESP_ENABLE_WOLFSSH
#define WOLFSSL_WOLFSSH

/* -- wolfSSH features -------------------------------------------- */
#define WOLFSSH_TEST_SERVER         /* enable server-side API        */
#define WOLFSSH_TERM                /* accept PTY requests           */
#define WOLFSSH_SHELL               /* enable window-change resize callback */
#define DEFAULT_WINDOW_SZ  2000    /* shrunk for embedded use       */

/* -- Crypto: ED25519 only (SCEP enrollment now uses mbedTLS RSA) -- */
/* RSA is no longer compiled into wolfSSL.  SCEP uses mbedTLS directly. */
#define HAVE_ECC
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_SHA512              /* required by ED25519           */
#define USE_FAST_MATH

/* Disable RSA in wolfSSL -- SCEP uses mbedTLS for all RSA operations */
#define NO_RSA
#define WOLFSSH_NO_RSA

/* -- Embedded constraints ---------------------------------------- */
#define NO_FILESYSTEM
#define NO_OLD_TLS
#define WOLFSSL_SMALL_STACK

/* -- ESP32 hardware acceleration --------------------------------- */
#define NO_WOLFSSL_ESP32_CRYPT_HASH_SHA224
