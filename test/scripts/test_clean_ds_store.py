#!/usr/bin/env python3
"""
test/scripts/test_clean_ds_store.py
===================================
Tests for scripts/clean_ds_store.py -- the PlatformIO pre-script that strips
stray macOS .DS_Store turds out of managed_components/ before a build.

The audited bug (S-F2): the script called os.listdir(managed_components)
unconditionally.  On a clean checkout that directory does not exist yet, so
the listdir raised FileNotFoundError and aborted the whole PlatformIO build
before it had a chance to start.  The fix guards the listdir with
os.path.isdir().

clean_ds_store.py is a SCons pre-script: it begins with `Import("env")`,
which is a builtin injected by the SCons/PlatformIO build environment and is
NOT importable under plain pytest.  We therefore execute the script's source
in a controlled namespace where `Import` and `env` are faked, pointing the
managed_components path at a temp directory we control.

Cases
-----
1. managed_components absent  -> no crash (the S-F2 regression guard).
2. managed_components present with a .DS_Store -> the file is removed.
3. managed_components present without a .DS_Store -> nothing removed,
   other files untouched.
4. Source-level guard: os.path.isdir appears before the listdir.

No network, no hardware, no ESP-IDF, no PlatformIO required.
Run with:
    venv/bin/pytest test/scripts/test_clean_ds_store.py -v
"""

import os

import pytest

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", ".."))
_CDS_PATH = os.path.join(_PROJECT_DIR, "scripts", "clean_ds_store.py")


class _FakeEnv:
    """Minimal stand-in for the SCons construction environment.

    The script only ever calls env.subst("$PROJECT_DIR/managed_components");
    we resolve that to a caller-supplied directory.
    """

    def __init__(self, managed_dir):
        self._managed_dir = managed_dir

    def subst(self, s):
        return s.replace("$PROJECT_DIR/managed_components", self._managed_dir)


def _run_clean_ds_store(managed_dir):
    """Execute scripts/clean_ds_store.py with a faked SCons namespace.

    Returns nothing; raises whatever the script raises (so a regression of
    the FileNotFoundError guard surfaces as a test failure).
    """
    with open(_CDS_PATH, "r") as f:
        src = f.read()

    ns = {
        "__name__": "clean_ds_store",
        "__file__": _CDS_PATH,
        # `Import("env")` is a SCons builtin; emulate it as a no-op since we
        # pre-seed `env` in the namespace below.
        "Import": lambda *_a, **_k: None,
        "env": _FakeEnv(managed_dir),
    }
    code = compile(src, _CDS_PATH, "exec")
    exec(code, ns)  # noqa: S102 -- executing project source under test


# ---------------------------------------------------------------------------
# 1. Clean checkout: managed_components/ does not exist -> must not crash.
# ---------------------------------------------------------------------------
def test_no_crash_when_managed_components_absent(tmp_path):
    managed = os.path.join(str(tmp_path), "managed_components")
    assert not os.path.exists(managed)
    # Before the fix this raised FileNotFoundError and aborted the build.
    _run_clean_ds_store(managed)
    # Still absent -- the script must not have created it either.
    assert not os.path.exists(managed)


# ---------------------------------------------------------------------------
# 2. .DS_Store present -> removed.
# ---------------------------------------------------------------------------
def test_removes_ds_store_when_present(tmp_path):
    managed = tmp_path / "managed_components"
    managed.mkdir()
    ds = managed / ".DS_Store"
    ds.write_bytes(b"\x00\x01macos junk")
    assert ds.exists()

    _run_clean_ds_store(str(managed))

    assert not ds.exists(), ".DS_Store should have been removed"


# ---------------------------------------------------------------------------
# 3. No .DS_Store -> nothing removed, real files survive.
# ---------------------------------------------------------------------------
def test_leaves_other_files_untouched(tmp_path):
    managed = tmp_path / "managed_components"
    managed.mkdir()
    keep = managed / "espressif__mdns"
    keep.mkdir()
    real = managed / "idf_component.yml"
    real.write_text("dependencies: {}\n")

    _run_clean_ds_store(str(managed))

    assert keep.is_dir(), "unrelated component dir must survive"
    assert real.is_file(), "unrelated file must survive"


# ---------------------------------------------------------------------------
# 4. Source-level guard: isdir() check precedes the listdir.
# ---------------------------------------------------------------------------
def test_source_has_isdir_guard_before_listdir():
    with open(_CDS_PATH, "r") as f:
        src = f.read()
    assert "os.path.isdir(" in src, \
        "isdir guard missing (S-F2 regression)"
    isdir_at = src.index("os.path.isdir(")
    listdir_at = src.index("os.listdir(")
    assert isdir_at < listdir_at, \
        "isdir guard must come before listdir (S-F2 regression)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
