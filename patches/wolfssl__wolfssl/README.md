# patches/wolfssl__wolfssl

## 0001-rename-thread_local-enum-value-to-avoid-C11-keyword-conflict.patch

**File patched:**
`managed_components/wolfssl__wolfssl/wolfcrypt/src/port/Espressif/esp_sdk_mem_lib.c`

The file defines a `sdk_memory_segment` enum that includes a value named
`thread_local`. C11 reserves `thread_local` as a keyword -- it is a synonym for
`_Thread_local` introduced by the C11 standard. ESP-IDF compiles all C sources
with `-std=c11`, so GCC rejects the enum declaration with a syntax error before
any object code is produced. The patch renames the enum value to
`thread_local_seg` in both the enum declaration (line 125 of the original file)
and the one call site that passes it to `sdk_log_meminfo` inside the
`CONFIG_IDF_TARGET_ARCH_XTENSA` guard.

The `esp_sdk_mem_lib.c` file is a diagnostic memory-inspection utility with no
role in the SSH or USB-CDC data path. The bridge component wrapper at
`components/wolfssl/CMakeLists.txt` already excludes it from compilation
because the file references linker-section boundary symbols (`_thread_local_start`,
`_thread_local_end`, etc.) as ordinary C variables, which is incompatible with
the PlatformIO/CMake build environment. The patch is therefore defensive: it
ensures the file is syntactically valid C11 so that any future build
configuration that does include it will not fail with a cryptic keyword conflict
rather than a clear linker error about the missing symbols.

## 0002-adapt-esp32-aes-sha-to-idf6-periph-clock-api.patch

**Files patched:**
- `managed_components/wolfssl__wolfssl/CMakeLists.txt`
- `managed_components/wolfssl__wolfssl/wolfcrypt/src/port/Espressif/esp32_aes.c`
- `managed_components/wolfssl__wolfssl/wolfcrypt/src/port/Espressif/esp32_sha.c`

ESP-IDF 6.0 removed `PERIPH_AES_MODULE` and `PERIPH_SHA_MODULE` from the
`shared_periph_module_t` enum in `soc/periph_defs.h`, and moved `hal/clk_gate_ll.h`
into the `esp_hal_clock` component which is not in the public include path for
user code. wolfSSL 5.8.2's `esp32_aes.c` and `esp32_sha.c` still call
`periph_module_enable/disable(PERIPH_AES_MODULE)` and
`periph_module_enable/disable(PERIPH_SHA_MODULE)`, and `esp32_sha.c` includes
`<hal/clk_gate_ll.h>` directly.

The patch replaces the removed API with the IDF 6 equivalents:

- `periph_module_enable(PERIPH_AES_MODULE)` → `esp_crypto_aes_enable_periph_clk(true)`
- `periph_module_disable(PERIPH_AES_MODULE)` → `esp_crypto_aes_enable_periph_clk(false)`
- `periph_module_enable(PERIPH_SHA_MODULE)` → `esp_crypto_sha_enable_periph_clk(true)`
- `periph_module_disable(PERIPH_SHA_MODULE)` → `esp_crypto_sha_enable_periph_clk(false)`
- All `#include <hal/clk_gate_ll.h>` lines → removed; replaced with
  `#include "esp_crypto_periph_clk.h"` (from `esp_security` component)

The `esp_unroll_sha_module_enable` function's ESP32-S2/S3 branch previously called
`periph_ll_periph_enabled(PERIPH_SHA_MODULE)` to check the clock-enable register
in a busy loop. In IDF 6.0 that function no longer accepts `PERIPH_SHA_MODULE`
(the enum value was removed). The replacement uses `ctx->lockDepth` as the
iteration bound, which matches the value the function was tracking anyway.

`components/wolfssl/CMakeLists.txt` adds `esp_security` to `PRIV_REQUIRES` so
that `esp_crypto_periph_clk.h` and its implementation are linked in. The bridge
component already `PRIV_REQUIRES esp_hw_support`, which in turn already
`priv_requires esp_hal_security esp_hal_clock`; adding `esp_security` directly
ensures the header is findable and the symbols link.

**Version compatibility:** Developed and verified against wolfSSL 5.8.2~1 with
ESP-IDF 6.0.1. The `#if defined(CONFIG_IDF_TARGET_ESP32S2)||...ESP32S3` guard
structure is preserved so the original ESP32 (non-S3) code path (which uses
`DPORT_PERI_CLK_EN_REG` directly) continues to compile for that target.
