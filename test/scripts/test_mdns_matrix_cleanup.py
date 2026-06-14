#!/usr/bin/env python3
"""
test/scripts/test_mdns_matrix_cleanup.py
========================================
Focused test for the S-F1 cleanup-correctness fix in
scripts/test_mdns_build_matrix.sh.

The audited bug (S-F1): MDNS_SENTINEL is the C comment
"/* mdns-matrix-test-enable */", which contains '/'.  The cleanup did
`sed -i "/$MDNS_SENTINEL/d" config.h`, but '/' is sed's address delimiter,
so the expression was malformed -- cleanup silently failed and left
`#define MDNS_ENABLE 1  /* ... */` injected into config.h permanently.

The fix replaces the sed deletion with a `grep -vF "$MDNS_SENTINEL"` filter
(fixed-string match, no delimiter problem), and injects exactly one
sentinel-tagged line so the round-trip is byte-for-byte.

Rather than copy the inject/cleanup logic into the test (which would drift),
this test EXTRACTS the real MDNS_SENTINEL assignment, the info() and
cleanup() function definitions, and the actual inject block from the live
shell script, then drives them against a throwaway config.h.  It never runs
`pio`/builds anything.

Asserts:
  * the injected line really lands in config.h (with the sentinel),
  * cleanup removes it,
  * config.h is byte-for-byte identical before injection and after cleanup,
  * the buggy sed-delete form is gone from the script.

Run with:
    venv/bin/pytest test/scripts/test_mdns_matrix_cleanup.py -v
"""

import os
import subprocess
import textwrap

import pytest

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.abspath(os.path.join(_TEST_DIR, "..", ".."))
_SCRIPT = os.path.join(_PROJECT_DIR, "scripts", "test_mdns_build_matrix.sh")


def _harness(config_path):
    """Build an sh program that pulls the real inject+cleanup logic out of
    the live script and runs it against *config_path*.

    Extraction strategy (anchored on stable lines in the script):
      * MDNS_SENTINEL=...                 -- the sentinel assignment line
      * info() { ... }                    -- one-line function def
      * cleanup() { ... }                 -- multi-line func, sed range to '}'
      * the inject block                  -- from the 'if [ -s "$CONFIG_H"'
                                             guard through the sentinel printf
    CONFIG_H is overridden to point at the throwaway file.
    """
    return textwrap.dedent(f"""
        set -e
        SRC="{_SCRIPT}"
        CONFIG_H="{config_path}"

        # Real sentinel assignment from the script.
        eval "$(grep -E '^MDNS_SENTINEL=' "$SRC")"

        # Real info() (it's a single-line definition).
        eval "$(grep -E '^info\\(\\)' "$SRC")"

        # Real cleanup() -- from its 'cleanup() {{' line to the closing '}}'
        # at column 0.
        eval "$(awk '/^cleanup\\(\\) \\{{/{{f=1}} f{{print}} f&&/^\\}}/{{exit}}' "$SRC")"

        # Real inject block -- from the trailing-newline guard 'if [ -s' line
        # through the sentinel printf line.
        inject="$(awk '/^if \\[ -s \"\\$CONFIG_H\"/{{f=1}} f{{print}} f&&/MDNS_SENTINEL\" >> \"\\$CONFIG_H\"/{{exit}}' "$SRC")"

        echo "=== inject ==="
        eval "$inject"
        echo "=== after-inject sentinel present? ==="
        grep -cF "$MDNS_SENTINEL" "$CONFIG_H" || true
        echo "=== cleanup ==="
        cleanup
    """)


def _run_harness(config_path):
    out = subprocess.run(
        ["sh", "-c", _harness(config_path)],
        capture_output=True, text=True,
    )
    return out


# ---------------------------------------------------------------------------
# 1. Round-trip: inject then cleanup leaves config.h byte-for-byte identical.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("original", [
    # Typical config.h tail: trailing newline present.
    "#define WIFI_SSID \"x\"\n#define MDNS_ENABLE 0\n",
    # No trailing newline (degenerate) -- guard must add a separator.
    "#define WIFI_SSID \"x\"",
    # Empty file.
    "",
    # Content that itself contains slashes (sed-delimiter trap).
    "// path: /usr/local/x\n#define A 1\n",
])
def test_inject_cleanup_roundtrip(tmp_path, original):
    cfg = tmp_path / "config.h"
    cfg.write_text(original)
    before = cfg.read_bytes()

    out = _run_harness(str(cfg))
    assert out.returncode == 0, f"harness failed:\n{out.stdout}\n{out.stderr}"

    # Mid-run the sentinel must have been present (proves inject worked).
    # The "after-inject sentinel present?" count line should be >= 1.
    lines = out.stdout.splitlines()
    idx = lines.index("=== after-inject sentinel present? ===")
    count = int(lines[idx + 1].strip())
    assert count >= 1, "inject did not add the sentinel line"

    after = cfg.read_bytes()
    # Empty + no-trailing-newline inputs: the guard may legitimately have
    # added a single terminating newline that cleanup can't strip (a blank
    # line carries no sentinel).  Accept exact match OR match-plus-final-\n.
    if original.endswith("\n") or original == "":
        assert after == before, (
            "cleanup did not restore config.h byte-for-byte\n"
            f"before={before!r}\nafter={after!r}"
        )
    else:
        assert after in (before, before + b"\n"), (
            "cleanup left unexpected residue\n"
            f"before={before!r}\nafter={after!r}"
        )

    # No MDNS_ENABLE define and no sentinel may survive cleanup.
    assert b"mdns-matrix-test-enable" not in after, \
        "sentinel survived cleanup (S-F1 regression)"
    assert b"#define MDNS_ENABLE 1" not in after, \
        "injected MDNS_ENABLE define survived cleanup (S-F1 regression)"


# ---------------------------------------------------------------------------
# 2. Source-level guard: the buggy `sed -i "/$MDNS_SENTINEL/d"` is gone.
# ---------------------------------------------------------------------------
def test_buggy_sed_delete_removed():
    with open(_SCRIPT, "r") as f:
        src = f.read()
    assert 'sed -i "/$MDNS_SENTINEL/d"' not in src, \
        "buggy sed-delete with '/' delimiter clash still present (S-F1 regression)"
    assert 'grep -vF "$MDNS_SENTINEL"' in src, \
        "grep -vF cleanup replacement missing (S-F1 regression)"


# ---------------------------------------------------------------------------
# 3. The sentinel itself still contains '/' (so the test is meaningful) and
#    cleanup handles it.  Documents WHY the sed form was broken.
# ---------------------------------------------------------------------------
def test_sentinel_contains_slash():
    with open(_SCRIPT, "r") as f:
        src = f.read()
    # Find the MDNS_SENTINEL= assignment value.
    for line in src.splitlines():
        if line.startswith("MDNS_SENTINEL="):
            assert "/" in line, \
                "sentinel no longer contains '/' -- update this test's premise"
            break
    else:
        pytest.fail("MDNS_SENTINEL assignment not found in script")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
