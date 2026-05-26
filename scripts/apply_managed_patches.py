"""
apply_managed_patches.py -- PlatformIO extra_script (pre:)

Re-applies patches from patches/<component>/*.patch to managed_components/<component>/
after each dependency fetch. Idempotent: skips already-applied patches using
`patch --dry-run -R` (reverse-apply check).

Usage in platformio.ini:
    extra_scripts = pre:scripts/apply_managed_patches.py
                    post:scripts/gen_eap_certs_asm.py
"""

import os
import subprocess
import glob

Import("env")  # noqa: F821 -- PlatformIO SCons environment

PROJECT_DIR = env.subst("$PROJECT_DIR")
PATCHES_DIR = os.path.join(PROJECT_DIR, "patches")
MC_DIR = os.path.join(PROJECT_DIR, "managed_components")


def _run(cmd, cwd, check=True):
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Command {cmd} timed out after 300 s in {cwd}"
        )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd} failed in {cwd}:\n"
            f"stdout: {result.stdout.decode()}\n"
            f"stderr: {result.stderr.decode()}"
        )
    return result


def apply_patches():
    if not os.path.isdir(PATCHES_DIR):
        return  # nothing to do

    for component_dir in sorted(os.listdir(PATCHES_DIR)):
        patch_subdir = os.path.join(PATCHES_DIR, component_dir)
        if not os.path.isdir(patch_subdir):
            continue

        component_path = os.path.join(MC_DIR, component_dir)
        if not os.path.isdir(component_path):
            # Component not yet fetched -- skip silently, will apply next time.
            print(f"[patches] managed_components/{component_dir} not present, skipping patches")
            continue

        patch_files = sorted(glob.glob(os.path.join(patch_subdir, "*.patch")))
        for patch_file in patch_files:
            patch_name = os.path.relpath(patch_file, PATCHES_DIR)

            # Check if already applied by trying a dry-run reverse apply.
            check_result = _run(
                ["patch", "--dry-run", "-R", "-p1", "-i", patch_file],
                cwd=component_path,
                check=False,
            )
            if check_result.returncode == 0:
                # Reverse succeeds -> patch is already applied, skip.
                print(f"[patches] Already applied: {patch_name}")
                continue

            # Check if patch applies forward cleanly (dry-run).
            forward_check = _run(
                ["patch", "--dry-run", "-p1", "-i", patch_file],
                cwd=component_path,
                check=False,
            )
            if forward_check.returncode != 0:
                raise RuntimeError(
                    f"[patches] Patch {patch_name} cannot be applied (already partially applied "
                    f"or upstream changed):\n{forward_check.stderr.decode()}"
                )

            # Apply the patch.
            _run(["patch", "-p1", "-i", patch_file], cwd=component_path)
            print(f"[patches] Applied: {patch_name}")


apply_patches()
