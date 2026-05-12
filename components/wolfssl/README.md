# components/wolfssl

This directory is a hand-written ESP-IDF component whose sole purpose is to
bridge PlatformIO's build system to the wolfSSL cryptography library. wolfSSL
itself is fetched by the IDF Component Manager and lands in
`managed_components/wolfssl__wolfssl/`; the companion wolfSSH library lands in
`managed_components/wolfssl__wolfssh/`. wolfSSH declares a `REQUIRES wolfssl`
dependency, but the auto-generated component wrapper that the IDF Component
Manager places alongside the downloaded source never satisfies that dependency
in a PlatformIO + ESP-IDF build -- the `FIND_WOLFSSL_DIRECTORY` logic in the
upstream CMakeLists.txt fails to locate the sibling managed component at
configure time. This bridge component fixes that: it registers itself as the
`wolfssl` IDF component, compiles wolfSSL's sources directly, and exposes the
headers that the rest of the firmware needs.

## CMakeLists.txt

`CMakeLists.txt` opens with a `file(GLOB ...)` that collects every `.c` file
under `managed_components/wolfssl__wolfssl/src/`, `wolfcrypt/src/`, and
`wolfcrypt/src/port/Espressif/`. A curated exclusion list then removes files
that are either disabled by `user_settings.h` (OpenSSL-compat shims such as
`bio.c`, `conf.c`, `pk.c`, the `x509*` and `ssl_*` split files), unneeded
algorithm back-ends (all `sp_sm2_*` variants, `ext_kyber.c`, `evp.c`), and
one Espressif utility (`esp_sdk_mem_lib.c`) that uses `thread_local` as an
enum identifier -- a C11 keyword conflict that breaks the xtensa-esp-elf-gcc
toolchain. Xtensa `.S` assembly files are removed with a second glob pass
because they are not valid for the toolchain invocation used by PlatformIO.
The `idf_component_register` call lists wolfSSL's own include trees as
`INCLUDE_DIRS` alongside this component's `include/` subdirectory, and adds
`PRIV_REQUIRES esp_hw_support` so that the Espressif HW acceleration files
(`esp32_aes.c`, `esp32_sha.c`) can resolve the `periph_ctrl` clock-gating
symbols present in ESP-IDF 5.4 LTS.

## include/user_settings.h

wolfSSL is compiled with `-DWOLFSSL_USER_SETTINGS`, which suppresses the
library's own `settings.h` auto-detection and delegates every feature decision
to `include/user_settings.h`. This file is also the configuration header for
wolfSSH (the macro names starting with `WOLFSSH_` are read by wolfSSH at
compile time). The ESP32 platform macros (`WOLFSSL_ESPIDF`, `WOLFSSL_ESP32`,
`ESP_ENABLE_WOLFSSH`) are set first so that wolfSSL's Espressif port files
activate correctly. wolfSSH terminal and shell support is enabled via
`WOLFSSH_TERM` and `WOLFSSH_SHELL`, and `DEFAULT_WINDOW_SZ` is reduced to
2000 bytes to stay within the ESP32-S3's DRAM budget. On the cryptography
side only ED25519 is compiled as a host-key and public-key authentication
algorithm -- RSA is disabled (`NO_RSA`, `WOLFSSH_NO_RSA`) to save
approximately 40 KB of flash. `HAVE_ECC`, `HAVE_CURVE25519`, and
`HAVE_ED25519` are defined together with `WOLFSSL_ED25519_STREAMING_VERIFY`
(required by wolfSSH's verify path) and `WOLFSSL_SHA512` (required by the
Ed25519 hash). `USE_FAST_MATH` selects wolfSSL's portable integer arithmetic
back-end. `NO_FILESYSTEM` and `WOLFSSL_SMALL_STACK` reflect the embedded
constraint that there is no POSIX file system and that heap allocations should
be minimised.

## Cipher hardening

The negotiated cipher suite is intentionally narrow. `HAVE_AESGCM` is the
only symmetric cipher enabled; AES-CBC is excluded (`WOLFSSH_NO_AES_CBC`) to
remove the padding-oracle attack surface, and AES-192 is stripped entirely at
the wolfSSL level via `NO_AES_192` -- both because the ESP32-S3 AES peripheral
only supports 128-bit and 256-bit keys (silicon limitation, wolfSSL issue
#6375), and to ensure that `aes192-gcm@openssh.com` cannot be selected even
if a future client attempts to negotiate it. SHA-1 MAC algorithms
(`WOLFSSH_NO_HMAC_SHA1`, `WOLFSSH_NO_HMAC_SHA1_96`) and Diffie-Hellman key
exchange (`WOLFSSH_NO_DH`) are disabled in favour of ECDH/X25519. The runtime
cipher list is further pinned to `aes256-gcm@openssh.com` only via
`wolfSSH_CTX_SetAlgoListCipher` in `main/ssh_server.c`, providing a second
layer of enforcement independent of compile-time knobs.

## Hardware acceleration

Both `esp32_sha.c` and `esp32_aes.c` are intentionally kept in the compiled
source set (they are not in the exclusion list). When the firmware runs on the
ESP32-S3, wolfSSL will offload SHA-256/384/512 and AES-128-GCM/AES-256-GCM to
the on-chip SHA and AES peripherals. `NO_WOLFSSL_ESP32_CRYPT_AES_192` is
declared redundantly (AES-192 code is already absent due to `NO_AES_192`) as
an explicit guard against any future partial re-enablement. The
`-DWOLFSSL_ROOT` cmake extra argument in `platformio.ini` points wolfSSH's own
CMakeLists.txt at the managed-components path so that header resolution during
wolfSSH's configure step finds the same tree that this bridge component
compiles.
