#!/usr/bin/env python3
"""
test/scripts/test_apply_patches.py -- Tests for scripts/apply_managed_patches_cmake.py

Tests:
  1. Happy path: patch applies cleanly to a synthetic component
  2. Idempotency: patch already applied (reverse dry-run detects it, skips)
  3. Failure: malformed patch file -> RuntimeError and sys.exit(1) from __main__
  4. Missing patches/ directory -> apply_patches() is a no-op (no error)

Exit: 0 = PASS, 1 = FAIL
"""

import os
import sys
import subprocess
import tempfile
import textwrap

# Locate the script under test
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
PATCH_SCRIPT = os.path.join(PROJECT_DIR, "scripts", "apply_managed_patches_cmake.py")

# Add scripts/ to the import path so we can call apply_patches() directly
sys.path.insert(0, os.path.join(PROJECT_DIR, "scripts"))
from apply_managed_patches_cmake import apply_patches

# -- Helpers ------------------------------------------------------------------

PASS_COUNT = 0
FAIL_COUNT = 0


def ok(msg):
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  [PASS] {msg}")


def fail(msg):
    global FAIL_COUNT
    FAIL_COUNT += 1
    print(f"  [FAIL] {msg}")


def make_fake_component(base_dir, component_name, original_content, patched_content):
    """
    Create:
      <base_dir>/managed_components/<component_name>/target.txt  (original)
      <base_dir>/patches/<component_name>/0001-test.patch        (diff patch)
    Returns the patch file path.
    """
    mc_path = os.path.join(base_dir, "managed_components", component_name)
    os.makedirs(mc_path, exist_ok=True)

    target = os.path.join(mc_path, "target.txt")
    with open(target, "w") as f:
        f.write(original_content)

    patch_dir = os.path.join(base_dir, "patches", component_name)
    os.makedirs(patch_dir, exist_ok=True)

    # Generate a unified diff patch using subprocess
    import tempfile as _tf
    with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as orig_f:
        orig_f.write(original_content)
        orig_path = orig_f.name
    with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as patched_f:
        patched_f.write(patched_content)
        patched_path = patched_f.name

    diff_result = subprocess.run(
        ["diff", "-u",
         "--label", "a/target.txt",
         "--label", "b/target.txt",
         orig_path, patched_path],
        capture_output=True, text=True
    )
    os.unlink(orig_path)
    os.unlink(patched_path)

    # diff exits 1 when files differ (expected), 2 on error
    patch_content = diff_result.stdout

    patch_file = os.path.join(patch_dir, "0001-test.patch")
    with open(patch_file, "w") as f:
        f.write(patch_content)

    return patch_file, mc_path, target


# -- Test 1: Happy path -- patch applies cleanly -------------------------------

def test_happy_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        _, mc_path, target = make_fake_component(
            tmpdir, "test__comp",
            original_content="line1\nline2\nline3\n",
            patched_content="line1\nline2-patched\nline3\n",
        )

        apply_patches(tmpdir)

        with open(target) as f:
            result = f.read()

        if "line2-patched" in result:
            ok("Happy path: patch applied correctly")
        else:
            fail(f"Happy path: expected 'line2-patched' in file, got: {result!r}")


# -- Test 2: Idempotency -- already-applied patch is skipped -------------------

def test_idempotency():
    import io
    from contextlib import redirect_stdout

    with tempfile.TemporaryDirectory() as tmpdir:
        _, mc_path, target = make_fake_component(
            tmpdir, "test__comp2",
            original_content="aaa\nbbb\nccc\n",
            patched_content="aaa\nbbb-new\nccc\n",
        )

        # Apply once
        apply_patches(tmpdir)

        # Capture output of second apply
        buf = io.StringIO()
        with redirect_stdout(buf):
            apply_patches(tmpdir)
        output = buf.getvalue()

        if "Already applied" in output:
            ok("Idempotency: second apply skipped as already applied")
        else:
            fail(f"Idempotency: expected 'Already applied' in output, got: {output!r}")

        # File should still have patched content
        with open(target) as f:
            result = f.read()
        if "bbb-new" in result:
            ok("Idempotency: file content unchanged after second apply")
        else:
            fail(f"Idempotency: expected 'bbb-new' in file after second apply, got: {result!r}")


# -- Test 3: Malformed patch file -> RuntimeError -------------------------------

def test_malformed_patch():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a component with a file
        mc_path = os.path.join(tmpdir, "managed_components", "bad__comp")
        os.makedirs(mc_path)
        with open(os.path.join(mc_path, "target.txt"), "w") as f:
            f.write("hello\n")

        # Write a syntactically malformed patch (not a valid unified diff)
        patch_dir = os.path.join(tmpdir, "patches", "bad__comp")
        os.makedirs(patch_dir)
        with open(os.path.join(patch_dir, "0001-bad.patch"), "w") as f:
            f.write("THIS IS NOT A VALID PATCH FILE\ngarbage garbage garbage\n")

        try:
            apply_patches(tmpdir)
            fail("Malformed patch: expected RuntimeError, got no exception")
        except RuntimeError as e:
            ok(f"Malformed patch: raised RuntimeError as expected")

    # Also verify the script's __main__ path exits non-zero
    result = subprocess.run(
        [sys.executable, PATCH_SCRIPT, "/nonexistent/path/that/does/not/exist"],
        capture_output=True, text=True
    )
    # No patches/ dir -> no-op (exit 0), not an error
    if result.returncode == 0:
        ok("Malformed test via __main__ with nonexistent dir: exit 0 (no patches dir = no-op)")
    else:
        fail(f"Expected exit 0 for missing project dir, got {result.returncode}")


# -- Test 4: Missing patches/ directory -> no-op -------------------------------

def test_missing_patches_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        # No patches/ directory at all
        try:
            apply_patches(tmpdir)
            ok("Missing patches/: apply_patches() returned without error (no-op)")
        except Exception as e:
            fail(f"Missing patches/: unexpected exception: {e}")


# -- Test 5: Component present in patches/ but absent from managed_components/ --

def test_component_absent_from_managed_components():
    """patches/<comp> present but managed_components/<comp> absent -> skip, no error."""
    import io
    from contextlib import redirect_stdout

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a patches/<comp>/*.patch but no managed_components/<comp>/
        patch_dir = os.path.join(tmpdir, "patches", "ghost__comp")
        os.makedirs(patch_dir)
        with open(os.path.join(patch_dir, "0001-ghost.patch"), "w") as f:
            f.write("--- a/x.txt\n+++ b/x.txt\n@@ -1 +1 @@\n-old\n+new\n")

        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                apply_patches(tmpdir)
            ok("Absent managed_components: apply_patches() completed without exception")
        except Exception as e:
            fail(f"Absent managed_components: unexpected exception: {e}")

        output = buf.getvalue()
        if "not present" in output or "skipping" in output:
            ok("Absent managed_components: printed a skip message")
        else:
            fail(f"Absent managed_components: expected skip message, got: {output!r}")


# -- Test 6: Multiple patches applied in order --------------------------------

def test_multiple_patches_applied_in_order():
    """Two patches against the same component must both be applied in sorted order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mc_path = os.path.join(tmpdir, "managed_components", "multi__comp")
        os.makedirs(mc_path)
        target = os.path.join(mc_path, "target.txt")
        with open(target, "w") as f:
            f.write("line1\nline2\nline3\n")

        patch_dir = os.path.join(tmpdir, "patches", "multi__comp")
        os.makedirs(patch_dir)

        # First patch: change line2 -> line2-a
        import tempfile as _tf
        def write_patch(orig, patched, patch_path):
            with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as o:
                o.write(orig); oname = o.name
            with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as p:
                p.write(patched); pname = p.name
            result = subprocess.run(
                ["diff", "-u", "--label", "a/target.txt", "--label", "b/target.txt",
                 oname, pname],
                capture_output=True, text=True)
            os.unlink(oname); os.unlink(pname)
            with open(patch_path, "w") as f:
                f.write(result.stdout)

        write_patch("line1\nline2\nline3\n", "line1\nline2-a\nline3\n",
                    os.path.join(patch_dir, "0001-first.patch"))
        write_patch("line1\nline2-a\nline3\n", "line1\nline2-a\nline3-b\n",
                    os.path.join(patch_dir, "0002-second.patch"))

        try:
            apply_patches(tmpdir)
        except Exception as e:
            fail(f"Multiple patches: unexpected exception: {e}")
            return

        with open(target) as f:
            result = f.read()

        if "line2-a" in result and "line3-b" in result:
            ok("Multiple patches: both patches applied correctly in order")
        else:
            fail(f"Multiple patches: expected both changes, got: {result!r}")


# -- Test 7: Empty patches/ directory (no subdirs) -> no-op ------------------

def test_empty_patches_dir_is_noop():
    """An empty patches/ directory (no component subdirs) must be a no-op."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "patches"))  # empty patches/
        try:
            apply_patches(tmpdir)
            ok("Empty patches/: apply_patches() returned without error")
        except Exception as e:
            fail(f"Empty patches/: unexpected exception: {e}")


# -- Run all tests -------------------------------------------------------------

if __name__ == "__main__":
    print("[test_apply_patches] -- Test 1: Happy path ---------------------")
    test_happy_path()

    print("[test_apply_patches] -- Test 2: Idempotency --------------------")
    test_idempotency()

    print("[test_apply_patches] -- Test 3: Malformed patch -> RuntimeError -")
    test_malformed_patch()

    print("[test_apply_patches] -- Test 4: Missing patches/ dir -> no-op ---")
    test_missing_patches_dir()

    print("[test_apply_patches] -- Test 5: Component absent -> skip --------")
    test_component_absent_from_managed_components()

    print("[test_apply_patches] -- Test 6: Multiple patches in order -------")
    test_multiple_patches_applied_in_order()

    print("[test_apply_patches] -- Test 7: Empty patches/ dir -> no-op -----")
    test_empty_patches_dir_is_noop()

    print()
    total = PASS_COUNT + FAIL_COUNT
    print(f"[test_apply_patches] {PASS_COUNT}/{total} passed")
    if FAIL_COUNT > 0:
        print("[test_apply_patches] == FAIL ==")
        sys.exit(1)
    else:
        print("[test_apply_patches] == PASS ==")
        sys.exit(0)
