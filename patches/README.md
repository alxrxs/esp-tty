# patches/ — Managed Component Patches

```
patches/
  wolfssl__wolfssl/
    0001-rename-thread_local-enum-value-to-avoid-C11-keyword-conflict.patch
```

## Why patches are stored here instead of in managed_components/

The IDF component manager stores fetched components in `managed_components/`,
which is **gitignored**. On every clean build (or `pio run` after deleting the
directory) the component manager re-fetches all components from the registry,
overwriting any local edits.

Storing patches separately and re-applying them at cmake configure time means:
- The patches are tracked in git.
- Clean builds reproduce the patched state automatically without manual steps.
- Upstream version bumps are detected (the patch will fail to apply if the
  target file has changed, prompting a review of the patch against the new
  version).

## How patches are applied

The root `CMakeLists.txt` calls `scripts/apply_managed_patches_cmake.py` via
`execute_process` as part of the cmake configure step. The script:

1. Scans `patches/<component>/*.patch` in lexicographic order.
2. For each patch, runs `patch --dry-run -R` against the target directory. If
   the patch reverses cleanly, it is already applied and is skipped.
3. If not already applied, runs `patch -p1` in the component directory.
4. Raises a `RuntimeError` (and cmake configure fails) if a patch cannot be
   applied.

The idempotency check means subsequent `pio run` invocations after the initial
fetch do not error or double-apply.

See `scripts/README.md` for the full documentation of
`apply_managed_patches_cmake.py`, and `test/scripts/README.md` for the
`test_apply_patches.py` test that covers the patching logic.

## Current patches

### wolfssl__wolfssl/0001-rename-thread_local-enum-value-to-avoid-C11-keyword-conflict.patch

**File patched:**
`managed_components/wolfssl__wolfssl/wolfcrypt/src/port/Espressif/esp_sdk_mem_lib.c`

**Problem:** The file uses `thread_local` as an enum value name:
```c
enum sdk_memory_segment {
    mem_map_io = 0,
    thread_local,       /* <-- conflicts with C11 keyword */
    data,
    ...
};
```

C11 (which ESP-IDF uses) reserves `thread_local` as a keyword (synonym for
`_Thread_local`). GCC with `-std=c11` rejects this enum declaration with a
syntax error.

**Fix:** Rename the enum value to `thread_local_seg` in both the enum
declaration and the one call site that references it.

**Upstream status:** The `esp_sdk_mem_lib.c` file is a diagnostic utility;
the bridge component in `components/wolfssl/` already excludes it from
compilation (it uses linker section symbols as C variables, which is
incompatible with the PlatformIO build). The patch is applied anyway to avoid
confusion if the file is ever included in a future build configuration.

**Adding new patches:** Place `.patch` files under
`patches/<idf_component_name>/`, where `<idf_component_name>` matches the
directory name under `managed_components/` (e.g., `wolfssl__wolfssl` for the
`wolfssl/wolfssl` IDF component). Number them sequentially
(`0001-`, `0002-`, ...) so they apply in order.
