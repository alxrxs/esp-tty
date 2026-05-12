# patches/ -- Managed Component Patches

This directory holds `git diff`-style patches for IDF components fetched by the
ESP-IDF component manager. Each subdirectory is named after the component it
targets, matching the directory name under `managed_components/` exactly (e.g.,
`wolfssl__wolfssh` for the `wolfssl/wolfssl` IDF component).

## Why patches live here instead of in managed_components/

The IDF component manager stores fetched components in `managed_components/`,
which is gitignored. On every clean build -- or any `pio run` after the directory
is deleted -- the component manager re-fetches all components from the registry,
overwriting any local edits. Patches stored here are tracked in version control
and re-applied automatically at cmake configure time, so the patched state is
reproduced on every build without manual intervention. A side benefit is that
version bumps are caught early: if an upstream component changes the patched
file, `patch` will refuse to apply and cmake configure fails with an explicit
error, prompting a review of the patch against the new upstream source.

## How patches are applied

`CMakeLists.txt` invokes `scripts/apply_managed_patches_cmake.py` via
`execute_process` during the cmake configure step, after the component manager
has resolved and fetched dependencies. The script:

1. Scans `patches/<component>/*.patch` in lexicographic order for each
   component subdirectory.
2. Runs `patch --dry-run -R -p1` against the target component directory. If the
   reverse dry-run succeeds, the patch is already applied and is skipped.
3. Runs a forward dry-run (`patch --dry-run -p1`) to verify the patch can be
   applied cleanly. If that fails, cmake configure aborts with a descriptive
   error (the patch context no longer matches, likely due to an upstream change).
4. Applies the patch with `patch -p1`.

The idempotency check means repeated `pio run` invocations after the initial
fetch do not double-apply patches or produce errors.

See `scripts/README.md` for the full documentation of
`apply_managed_patches_cmake.py`, and `test/scripts/README.md` for
`test_apply_patches.py`, which covers the patching logic end-to-end.

## Current patches

| Subdirectory | Patch file | Description |
|---|---|---|
| `wolfssl__wolfssl/` | `0001-rename-thread_local-enum-value-to-avoid-C11-keyword-conflict.patch` | Renames a `thread_local` enum value in wolfcrypt to avoid a C11 keyword conflict under `-std=c11`. |
| `wolfssl__wolfssh/` | `0001-expose-resize-cb-setters-without-NO_FILESYSTEM.patch` | Moves two terminal-resize callback setters out of a `!NO_FILESYSTEM` guard so they link correctly on the bare-metal ESP32-S3. |

Full context for each patch -- including the problem, the fix, upstream status,
and version compatibility -- is in the per-subdirectory `README.md` files.

## Adding a new patch

1. Make the desired edit directly in `managed_components/<component>/`.
2. Generate the patch from the project root:
   ```
   diff -u managed_components/<component>/path/to/original \
            managed_components/<component>/path/to/modified \
        > patches/<component>/0001-short-description.patch
   ```
   Or use `git diff` if you have staged the change inside the component
   directory. Number files sequentially (`0001-`, `0002-`, ...) so they apply
   in the correct order.
3. Place the `.patch` file under `patches/<idf_component_name>/`, creating the
   subdirectory if it does not already exist.
4. Add a `README.md` in the same subdirectory documenting the problem, the fix,
   upstream status, and the component version the patch was developed against.
5. Delete `managed_components/<component>/` (or run `pio run --target clean`),
   then rebuild to confirm the patch applies cleanly from scratch.
