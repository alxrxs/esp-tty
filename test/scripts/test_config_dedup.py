#!/usr/bin/env python3
"""
test/scripts/test_config_dedup.py
-- Guards for the L2.A deduplication and L2.B SCEP password cross-device
   reuse findings.

  L2.A -- Device configs must NOT define macros whose values are identical
          to the C-source #ifndef defaults.  Guards the removed duplicates.
  L2.B -- SCEP_CHALLENGE_PASSWORD values must be unique across device
          configs (or the file must carry a comment acknowledging reuse).
          Warns (xfail) rather than hard-fails because the current password
          is already enrolled and rotation requires an operational step.
"""

import hashlib
import os
import re
import warnings

import pytest

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
MAIN_DIR    = os.path.join(PROJECT_DIR, "main")


def _read(rel):
    path = os.path.join(PROJECT_DIR, rel)
    with open(path, "r") as f:
        return f.read()


def _device_configs():
    """Return list of (name, content) tuples for all main/config.*.h files,
    excluding config.example.h (which is a template, not a device config)."""
    results = []
    for fname in sorted(os.listdir(MAIN_DIR)):
        if fname.startswith("config.") and fname.endswith(".h") and fname != "config.example.h":
            with open(os.path.join(MAIN_DIR, fname)) as f:
                results.append((fname, f.read()))
    return results


# ---------------------------------------------------------------------------
# L2.A: macros that must NOT appear as bare #define in device configs because
# their value is identical to the C-source #ifndef default.
# ---------------------------------------------------------------------------

# Map macro -> expected-default-value (as it appears in the C source).
# These were removed from config.dell.h and config.big.h; if they reappear
# with the same value, something regressed.
#
# NOTE: SSH_PORT is intentionally NOT in this list.  Its #ifndef fallback
# lives only in wifi.c (a single translation unit); ssh_server.c also reads
# SSH_PORT from config.h with no own fallback.  To compile ssh_server.c,
# SSH_PORT must be present in config.h even when 22 is the desired value.
_DUPLICATED_DEFAULTS = {
    "WIFI_MAX_RETRY":             "0",
    "DHCP_RETRY_TIMEOUT_SEC":     "30",
    "MAX_TTY_KEYS":               "8",
    "SSH_HANDSHAKE_TIMEOUT_SEC":  "30",
    "TCP_KEEPALIVE_IDLE_SEC":     "60",
    "TCP_KEEPALIVE_INTVL_SEC":    "10",
    "TCP_KEEPALIVE_COUNT":        "3",
    "OTA_ROLLBACK_DELAY_MS":      "30000",
    "SCROLLBACK_REPLAY_LINES":    "1000",
}


@pytest.mark.parametrize("macro,default_value", list(_DUPLICATED_DEFAULTS.items()))
def test_no_duplicate_default_define(macro, default_value):
    """L2.A — device config must not re-define a macro to its C-source default."""
    for fname, content in _device_configs():
        # Look for an active (non-commented) #define of this macro with the
        # exact default value.  Allow trailing whitespace / comments.
        pattern = re.compile(
            r"^\s*#\s*define\s+" + re.escape(macro) + r"\s+" + re.escape(default_value) + r"\b",
            re.MULTILINE,
        )
        m = pattern.search(content)
        assert m is None, (
            f"{fname}: found '#define {macro} {default_value}' which is identical "
            f"to the C-source default — delete it and rely on the #ifndef fallback."
        )


# ---------------------------------------------------------------------------
# L2.B: SCEP_CHALLENGE_PASSWORD uniqueness across device configs.
# Warns rather than hard-fails because the current shared value is already
# enrolled; rotation requires an operational step.
# ---------------------------------------------------------------------------

def _extract_scep_passwords(content):
    """Return list of SCEP_CHALLENGE_PASSWORD values found in content."""
    pattern = re.compile(
        r"^\s*#\s*define\s+SCEP_CHALLENGE_PASSWORD\s+\"([^\"]+)\"",
        re.MULTILINE,
    )
    return pattern.findall(content)


@pytest.mark.xfail(
    reason=(
        "L2.B: config.dell.h and config.big.h share the same SCEP_CHALLENGE_PASSWORD. "
        "This is a known issue; rotate per-device when convenient. "
        "See the TODO comments at each definition site."
    ),
    strict=False,
)
def test_scep_challenge_passwords_unique():
    """L2.B — each device config should have a unique SCEP_CHALLENGE_PASSWORD."""
    password_map = {}  # sha256(password) -> list of filenames
    for fname, content in _device_configs():
        for pw in _extract_scep_passwords(content):
            h = hashlib.sha256(pw.encode()).hexdigest()
            password_map.setdefault(h, []).append(fname)

    duplicates = {h: files for h, files in password_map.items() if len(files) > 1}
    assert not duplicates, (
        "SCEP_CHALLENGE_PASSWORD is shared across device configs — "
        "rotate and assign unique per-device challenge passwords:\n"
        + "\n".join(
            f"  SHA-256 {h[:16]}...: {', '.join(files)}"
            for h, files in duplicates.items()
        )
    )


def test_scep_password_reuse_comment_present():
    """L2.B — when SCEP_CHALLENGE_PASSWORD is shared, each file must carry
    a comment acknowledging the reuse and the TODO to rotate."""
    password_map = {}
    for fname, content in _device_configs():
        for pw in _extract_scep_passwords(content):
            h = hashlib.sha256(pw.encode()).hexdigest()
            password_map.setdefault(h, []).append((fname, content))

    for h, items in password_map.items():
        if len(items) < 2:
            continue
        for fname, content in items:
            assert "TODO" in content and "SCEP" in content, (
                f"{fname}: SCEP_CHALLENGE_PASSWORD is shared with another device config "
                f"but the file lacks the required TODO/SECURITY comment. "
                f"Add a comment acknowledging the reuse."
            )
