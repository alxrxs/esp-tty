# components/ — Local IDF Components

```
components/
  wolfssl/
    CMakeLists.txt   wolfSSL bridge component registration
    include/         (empty — wolfSSL headers come from managed_components/)
```

## Why this component exists

ESP-IDF component manager fetches wolfSSL into `managed_components/wolfssl__wolfssl/`.
The wolfSSL component's own `CMakeLists.txt` (shipped with the package) searches
for its source tree via a cmake variable `FIND_WOLFSSL_DIRECTORY`. That search
does not locate sources inside `managed_components/` because the IDF component
manager layout does not match what the variable expects.

As a result, `wolfssl__wolfssh` (the wolfSSH component, which lists wolfSSL as a
`REQUIRES` dependency by the IDF component name `wolfssl`) cannot find its
dependency when using the upstream cmake registration.

This bridge component provides the IDF component name `wolfssl` and compiles the
wolfSSL sources directly using `file(GLOB ...)` over the known path:

```
managed_components/wolfssl__wolfssl/src/*.c
managed_components/wolfssl__wolfssl/wolfcrypt/src/*.c
managed_components/wolfssl__wolfssl/wolfcrypt/src/port/Espressif/*.c
```

The component mirrors the `COMPONENT_SRCEXCLUDE` list from the upstream
wolfSSL cmake (bio.c, conf.c, ssl_asn1.c, evp.c, misc.c, etc.) so that the
compiled source set matches what wolfSSH expects.

## Hardware crypto path

The wolfSSL Espressif port files (`wolfcrypt/src/port/Espressif/esp32_aes.c` and
`esp32_sha.c`) are included in the glob and are NOT excluded. These files use the
ESP32-S3 AES and SHA hardware peripherals for AES-256-GCM encryption and
SHA-256/512 hashing via the `periph_ctrl` API, which is present in ESP-IDF 5.4
LTS. The component declares `PRIV_REQUIRES esp_hw_support` to give those files
access to the clock-gating symbols they need.

The `esp_sdk_mem_lib.c` diagnostic file is excluded. It uses `thread_local` as
an enum value name, which conflicts with the C11 keyword. A patch in
`patches/wolfssl__wolfssl/` renames the conflicting identifier to
`thread_local_seg`; the patch is applied automatically at cmake configure time.
See `patches/README.md` for details.

## Assembly files

Xtensa assembly files (`wolfcrypt/src/*.S`) are globbed and then removed from
the source list with a second `file(GLOB)` call. PlatformIO's cmake invocation
for ESP-IDF does not pass the Xtensa assembler flags expected by these files, so
they are excluded.
