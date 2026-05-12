"""
apply_managed_patches_cmake.py -- invoked by CMakeLists.txt via execute_process

Applies patches from patches/<component>/*.patch to managed_components/<component>/
after IDF component manager has fetched dependencies (dependency resolution
happens earlier in the CMake configure step that calls this script).

Idempotent: uses `patch --dry-run -R` to skip already-applied patches.

Usage: python3 apply_managed_patches_cmake.py <project_dir>
"""

import os
import sys
import subprocess
import glob


def _run(cmd, cwd, check=True):
    result = subprocess.run(
        cmd,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd} failed in {cwd}:\n"
            f"stdout: {result.stdout.decode()}\n"
            f"stderr: {result.stderr.decode()}"
        )
    return result


def apply_patches(project_dir):
    patches_dir = os.path.join(project_dir, "patches")
    mc_dir = os.path.join(project_dir, "managed_components")

    if not os.path.isdir(patches_dir):
        return

    for component_dir in sorted(os.listdir(patches_dir)):
        patch_subdir = os.path.join(patches_dir, component_dir)
        if not os.path.isdir(patch_subdir):
            continue

        component_path = os.path.join(mc_dir, component_dir)
        if not os.path.isdir(component_path):
            print(
                f"[patches] managed_components/{component_dir} not present, "
                f"skipping patches",
                flush=True,
            )
            continue

        patch_files = sorted(glob.glob(os.path.join(patch_subdir, "*.patch")))
        for patch_file in patch_files:
            patch_name = os.path.relpath(patch_file, patches_dir)

            # Check if already applied via reverse dry-run.
            # On macOS BSD patch, if the patch is NOT applied, `patch -R` still
            # exits 0 after printing "Unreversed ... Ignore -R? [y]" and falling
            # through to a forward dry-run.  A clean reverse (no such message)
            # with exit 0 is the only reliable "already applied" signal.
            check_result = _run(
                ["patch", "--dry-run", "-R", "-p1", "-i", patch_file],
                cwd=component_path,
                check=False,
            )
            output = check_result.stdout.decode() + check_result.stderr.decode()
            if check_result.returncode == 0 and "Unreversed" not in output:
                print(f"[patches] Already applied: {patch_name}", flush=True)
                continue

            # Verify forward apply succeeds before committing.
            forward_check = _run(
                ["patch", "--dry-run", "-p1", "-i", patch_file],
                cwd=component_path,
                check=False,
            )
            if forward_check.returncode != 0:
                raise RuntimeError(
                    f"[patches] Patch {patch_name} cannot be applied "
                    f"(partially applied or upstream changed):\n"
                    f"{forward_check.stderr.decode()}"
                )

            _run(["patch", "-p1", "-i", patch_file], cwd=component_path)
            print(f"[patches] Applied: {patch_name}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <project_dir>", file=sys.stderr)
        sys.exit(1)

    try:
        apply_patches(sys.argv[1])
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
