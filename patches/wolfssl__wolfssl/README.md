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
