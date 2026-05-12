"""
fetch_managed_components.py -- PlatformIO extra_script (pre:)

Ensures managed_components/ are present before cmake runs.

On a clean checkout managed_components/ is gitignored and absent.
PlatformIO's cmake step fails early if EXTRA_COMPONENT_DIRS points to a
missing directory. This script fetches managed components via the
idf_component_manager Python API (from the ESP-IDF PlatformIO venv)
BEFORE cmake is invoked, so managed_components are always present.

Idempotent: skips the fetch if managed_components/wolfssl__wolfssl already
exists.

Usage in platformio.ini:
    extra_scripts =
        pre:scripts/fetch_managed_components.py
        post:scripts/gen_eap_certs_asm.py
"""

import os
import subprocess
import sys
import tempfile

Import("env")  # noqa: F821 -- PlatformIO SCons environment

PROJECT_DIR = env.subst("$PROJECT_DIR")
MC_DIR = os.path.join(PROJECT_DIR, "managed_components")
SENTINEL = os.path.join(MC_DIR, "wolfssl__wolfssl")

IDF_PATH = env.PioPlatform().get_package_dir("framework-espidf")
CORE_DIR = env.subst("$PROJECT_CORE_DIR")


def _get_idf_venv_python():
    """Return the path to the Python executable in the ESP-IDF PlatformIO venv."""
    penv_dir = os.path.join(CORE_DIR, "penv")
    if not os.path.isdir(penv_dir):
        return None

    for entry in sorted(os.listdir(penv_dir)):
        if entry.startswith(".espidf-"):
            candidate = os.path.join(penv_dir, entry, "bin", "python")
            if os.path.isfile(candidate):
                return candidate
    return None


_FETCH_SCRIPT = """
import sys
import os
import tempfile

project_dir = sys.argv[1]
lock_path   = sys.argv[2] if len(sys.argv) > 2 else None

from idf_component_manager.core import ComponentManager

# Prepare a temporary managed_components list file and local_components list.
# We don't need accurate values -- we just want the component manager to
# download the remote dependencies listed in main/idf_component.yml.
with tempfile.NamedTemporaryFile(suffix='.cmake', mode='w', delete=False) as mc_list:
    mc_list_path = mc_list.name

with tempfile.NamedTemporaryFile(suffix='.yml', mode='w', delete=False) as local_list:
    # Minimal YAML: just list the main component directory
    local_list.write('components:\\n')
    local_list.write('  - name: "main"\\n')
    local_list.write(f'    path: "{os.path.join(project_dir, "main")}"\\n')
    local_list_path = local_list.name

try:
    mgr = ComponentManager(project_dir, lock_path=lock_path, interface_version=4)
    mgr.prepare_dep_dirs(
        managed_components_list_file=mc_list_path,
        component_list_file=local_list_path,
        local_components_list_file=local_list_path,
    )
    print("[fetch_managed_components] ComponentManager.prepare_dep_dirs() OK")
except SystemExit as e:
    # exit(10) means "re-run needed due to missing kconfig" -- acceptable
    if e.code == 10:
        print("[fetch_managed_components] prepare_dep_dirs exited with 10 (kconfig re-run signal) -- OK")
    else:
        raise
finally:
    for f in (mc_list_path, local_list_path):
        try:
            os.unlink(f)
        except OSError:
            pass
"""


def fetch_components():
    if os.path.isdir(SENTINEL):
        return  # already fetched

    python = _get_idf_venv_python()
    if python is None:
        print(
            "[fetch_managed_components] WARNING: ESP-IDF venv Python not found; "
            "managed_components may be absent. "
            "Run `idf.py update-dependencies` manually from the project directory.",
            file=sys.stderr,
        )
        return

    lock_path = os.path.join(PROJECT_DIR, "dependencies.lock")

    print(
        "[fetch_managed_components] managed_components absent -- "
        "fetching via idf_component_manager ..."
    )

    # Write the helper script to a temp file and run it with the IDF venv Python.
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
        f.write(_FETCH_SCRIPT)
        script_path = f.name

    try:
        env_vars = os.environ.copy()
        env_vars["IDF_PATH"] = IDF_PATH
        env_vars.pop("IDF_TOOLS_PATH", None)

        result = subprocess.run(
            [python, script_path, PROJECT_DIR, lock_path],
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env_vars,
        )

        output = result.stdout.decode(errors="replace")
        if output.strip():
            print(output.rstrip())

        if result.returncode != 0:
            print(
                f"[fetch_managed_components] FAILED (exit {result.returncode})",
                file=sys.stderr,
            )
            env.Exit(1)
        elif not os.path.isdir(SENTINEL):
            print(
                "[fetch_managed_components] WARNING: fetch ran but "
                f"{SENTINEL} still missing -- cmake may fail",
                file=sys.stderr,
            )
        else:
            print("[fetch_managed_components] Dependencies fetched OK")
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


fetch_components()
