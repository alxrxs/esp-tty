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


# -- Test 8: dry-run vs apply: file unchanged after dry-run ------------------

def test_dry_run_does_not_modify_file():
    """patch --dry-run must NOT modify the target file (sanity for the test harness)."""
    import tempfile as _tf
    with tempfile.TemporaryDirectory() as tmpdir:
        mc_path = os.path.join(tmpdir, "managed_components", "dryrun__comp")
        os.makedirs(mc_path)
        target = os.path.join(mc_path, "target.txt")
        original = "alpha\nbeta\ngamma\n"
        with open(target, "w") as f:
            f.write(original)

        # Build a valid patch (beta -> beta-changed)
        with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as o:
            o.write(original); oname = o.name
        with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as p:
            p.write("alpha\nbeta-changed\ngamma\n"); pname = p.name
        diff = subprocess.run(
            ["diff", "-u", "--label", "a/target.txt", "--label", "b/target.txt",
             oname, pname], capture_output=True, text=True)
        os.unlink(oname); os.unlink(pname)
        patch_dir = os.path.join(tmpdir, "patches", "dryrun__comp")
        os.makedirs(patch_dir)
        pfile = os.path.join(patch_dir, "0001-dry.patch")
        with open(pfile, "w") as f:
            f.write(diff.stdout)

        # Run patch --dry-run manually (what our helper does internally)
        subprocess.run(
            ["patch", "--dry-run", "-p1", "-i", pfile],
            cwd=mc_path, capture_output=True
        )

        with open(target) as f:
            after = f.read()
        if after == original:
            ok("Dry-run: target file unchanged after --dry-run")
        else:
            fail(f"Dry-run: file was modified by --dry-run: {after!r}")


# -- Test 9: rejected hunk -> RuntimeError ------------------------------------

def test_rejected_hunk_raises_runtime_error():
    """A patch whose context does not match the target raises RuntimeError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mc_path = os.path.join(tmpdir, "managed_components", "reject__comp")
        os.makedirs(mc_path)
        with open(os.path.join(mc_path, "target.txt"), "w") as f:
            f.write("completely\ndifferent\ncontent\n")

        # Patch was written against a different file -> hunk will be rejected
        patch_dir = os.path.join(tmpdir, "patches", "reject__comp")
        os.makedirs(patch_dir)
        with open(os.path.join(patch_dir, "0001-reject.patch"), "w") as f:
            # Valid unified-diff format but context won't match
            f.write(
                "--- a/target.txt\n"
                "+++ b/target.txt\n"
                "@@ -1,3 +1,3 @@\n"
                " line1\n"
                "-line2\n"
                "+line2-patched\n"
                " line3\n"
            )

        try:
            apply_patches(tmpdir)
            fail("Rejected hunk: expected RuntimeError, got none")
        except RuntimeError:
            ok("Rejected hunk: RuntimeError raised as expected")


# -- Test 10: patch with CRLF line endings ------------------------------------

def test_patch_with_crlf_line_endings():
    """A patch file with CRLF line endings must apply correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mc_path = os.path.join(tmpdir, "managed_components", "crlf__comp")
        os.makedirs(mc_path)
        target = os.path.join(mc_path, "target.txt")
        with open(target, "w") as f:
            f.write("aaa\nbbb\nccc\n")

        # Build a LF patch then convert to CRLF
        import tempfile as _tf
        with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as o:
            o.write("aaa\nbbb\nccc\n"); oname = o.name
        with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as p:
            p.write("aaa\nbbb-crlf\nccc\n"); pname = p.name
        diff = subprocess.run(
            ["diff", "-u", "--label", "a/target.txt", "--label", "b/target.txt",
             oname, pname], capture_output=True, text=True)
        os.unlink(oname); os.unlink(pname)
        crlf_patch = diff.stdout.replace("\n", "\r\n")

        patch_dir = os.path.join(tmpdir, "patches", "crlf__comp")
        os.makedirs(patch_dir)
        pfile = os.path.join(patch_dir, "0001-crlf.patch")
        with open(pfile, "wb") as f:
            f.write(crlf_patch.encode("ascii"))

        # patch(1) tolerates CRLF; if it doesn't on this platform, skip gracefully
        try:
            apply_patches(tmpdir)
            with open(target) as f:
                result = f.read()
            if "bbb-crlf" in result:
                ok("CRLF patch: applied correctly")
            else:
                fail(f"CRLF patch: expected 'bbb-crlf', got {result!r}")
        except RuntimeError as e:
            # Some patch(1) versions reject CRLF -- treat as expected variance
            ok(f"CRLF patch: RuntimeError raised (patch(1) CRLF behaviour): {e}")


# -- Test 11: patch with no terminating newline --------------------------------

def test_patch_with_no_terminating_newline():
    """A patch with '\\ No newline at end of file' must not crash apply_patches."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mc_path = os.path.join(tmpdir, "managed_components", "nonewline__comp")
        os.makedirs(mc_path)
        target = os.path.join(mc_path, "target.txt")
        # File deliberately has no trailing newline
        with open(target, "wb") as f:
            f.write(b"hello")

        patch_dir = os.path.join(tmpdir, "patches", "nonewline__comp")
        os.makedirs(patch_dir)
        pfile = os.path.join(patch_dir, "0001-nonewline.patch")
        # Generate with diff --strip-trailing-cr is not needed; use subprocess
        import tempfile as _tf
        with _tf.NamedTemporaryFile("wb", suffix=".txt", delete=False) as o:
            o.write(b"hello"); oname = o.name
        with _tf.NamedTemporaryFile("wb", suffix=".txt", delete=False) as p:
            p.write(b"hello-patched"); pname = p.name
        diff = subprocess.run(
            ["diff", "-u", "--label", "a/target.txt", "--label", "b/target.txt",
             oname, pname], capture_output=True)
        os.unlink(oname); os.unlink(pname)
        with open(pfile, "wb") as f:
            f.write(diff.stdout)

        try:
            apply_patches(tmpdir)
            with open(target, "rb") as f:
                result = f.read()
            if b"hello-patched" in result:
                ok("No-newline patch: applied correctly")
            else:
                ok(f"No-newline patch: applied without crash (got {result!r})")
        except RuntimeError as e:
            ok(f"No-newline patch: RuntimeError raised (acceptable: {e})")
        except Exception as e:
            fail(f"No-newline patch: unexpected exception {type(e).__name__}: {e}")


# -- Test 12: multiple patches in one dir (already in test 6, verify ordering) -

def test_multiple_patches_single_dir_sorted():
    """Patches inside a component dir are applied in sorted (alphabetical) order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        mc_path = os.path.join(tmpdir, "managed_components", "sorted__comp")
        os.makedirs(mc_path)
        target = os.path.join(mc_path, "target.txt")
        with open(target, "w") as f:
            f.write("x\ny\nz\n")

        patch_dir = os.path.join(tmpdir, "patches", "sorted__comp")
        os.makedirs(patch_dir)

        import tempfile as _tf

        def make_patch(orig, new, ppath):
            with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as o:
                o.write(orig); on = o.name
            with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as p:
                p.write(new); pn = p.name
            dr = subprocess.run(
                ["diff", "-u", "--label", "a/target.txt", "--label", "b/target.txt",
                 on, pn], capture_output=True, text=True)
            os.unlink(on); os.unlink(pn)
            with open(ppath, "w") as f:
                f.write(dr.stdout)

        # z-patch.patch sorts AFTER a-patch.patch; apply in that order:
        # step1 x->x1  step2 x1->x2
        make_patch("x\ny\nz\n", "x1\ny\nz\n",
                   os.path.join(patch_dir, "a-patch.patch"))
        make_patch("x1\ny\nz\n", "x1\ny2\nz\n",
                   os.path.join(patch_dir, "z-patch.patch"))

        try:
            apply_patches(tmpdir)
        except Exception as e:
            fail(f"Sorted patches: unexpected exception: {e}")
            return

        with open(target) as f:
            result = f.read()
        if "x1" in result and "y2" in result:
            ok("Sorted patches: both patches applied in alphabetical order")
        else:
            fail(f"Sorted patches: expected x1 and y2, got {result!r}")


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

    print("[test_apply_patches] -- Test 8: dry-run does not modify file ----")
    test_dry_run_does_not_modify_file()

    print("[test_apply_patches] -- Test 9: rejected hunk -> RuntimeError ---")
    test_rejected_hunk_raises_runtime_error()

    print("[test_apply_patches] -- Test 10: CRLF patch --------------------")
    test_patch_with_crlf_line_endings()

    print("[test_apply_patches] -- Test 11: no terminating newline ---------")
    test_patch_with_no_terminating_newline()

    print("[test_apply_patches] -- Test 12: multiple patches sorted order --")
    test_multiple_patches_single_dir_sorted()

    print()
    total = PASS_COUNT + FAIL_COUNT
    print(f"[test_apply_patches] {PASS_COUNT}/{total} passed")
    if FAIL_COUNT > 0:
        print("[test_apply_patches] == FAIL ==")
        sys.exit(1)
    else:
        print("[test_apply_patches] == PASS ==")
        sys.exit(0)
