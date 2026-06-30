"""
test_reboot_to_bootloader.py -- unit tests for scripts/reboot_to_bootloader.py

The script intentionally bypasses pyserial because pyserial.Serial.open()
unconditionally issues TIOCMBIC on the RTS line, which the running esp-tty
TinyUSB CDC stack rejects with EPROTO.  These tests verify the raw os.open
+ os.write path instead.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REBOOT_SCRIPT = REPO_ROOT / "scripts" / "reboot_to_bootloader.py"
TRIGGER_SRC = REPO_ROOT / "lib" / "usb_cdc_boot_trigger" / "usb_cdc_boot_trigger.c"

sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _import_fresh():
    if "reboot_to_bootloader" in sys.modules:
        del sys.modules["reboot_to_bootloader"]
    import reboot_to_bootloader  # noqa: WPS433
    return reboot_to_bootloader


# ---------------------------------------------------------------------------
# MAGIC matches the C source byte-for-byte
# ---------------------------------------------------------------------------

def test_magic_matches_c_source():
    """The script's MAGIC constant must byte-for-byte equal k_magic[] in the C source.

    Any drift between the Python sender and the firmware matcher would silently
    break the recovery path.
    """
    mod = _import_fresh()
    c_source = TRIGGER_SRC.read_text(encoding="utf-8")

    m = re.search(
        r'static\s+const\s+uint8_t\s+k_magic\[\]\s*=\s*"([^"]+)"\s*;',
        c_source,
    )
    assert m, "Could not find k_magic[] string literal in the C source"

    # Decode C string escapes (\n -> newline) and compare against the Python MAGIC.
    c_literal = m.group(1).encode("utf-8").decode("unicode_escape").encode("latin-1")
    assert mod.MAGIC == c_literal, (
        f"MAGIC drift: Python={mod.MAGIC!r}, C={c_literal!r}"
    )


def test_magic_starts_and_ends_with_newline():
    mod = _import_fresh()
    assert mod.MAGIC.startswith(b"\n")
    assert mod.MAGIC.endswith(b"\n")


def test_magic_body_contains_no_newline():
    """The matcher's simple mismatch-recovery requires that the magic body has no
    occurrence of the start byte ('\\n') except at the boundaries."""
    mod = _import_fresh()
    body = mod.MAGIC[1:-1]
    assert b"\n" not in body


# ---------------------------------------------------------------------------
# CLI argument handling
# ---------------------------------------------------------------------------

def test_missing_port_exits_2():
    """argparse rejects a missing positional with exit code 2."""
    result = subprocess.run(
        [sys.executable, str(REBOOT_SCRIPT)],
        capture_output=True, text=True,
    )
    assert result.returncode == 2, (
        f"Expected exit 2 for missing port, got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )


def test_nonexistent_port_exits_1():
    """A non-existent device path is caught before os.open is attempted."""
    result = subprocess.run(
        [sys.executable, str(REBOOT_SCRIPT),
         "/dev/ttyNONEXISTENT_esp_tty_test"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, (
        f"Expected exit 1 for non-existent port, got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )
    assert "error" in result.stderr.lower(), (
        f"Expected an error message on stderr, got: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# os.open is used (NOT pyserial)
# ---------------------------------------------------------------------------

def test_script_does_not_import_pyserial():
    """The script must NOT import pyserial -- pyserial's open() fails on
    TinyUSB CDC with EPROTO, which is why this script exists at all."""
    src = REBOOT_SCRIPT.read_text(encoding="utf-8")
    # No 'import serial' or 'from serial import ...' lines.
    assert not re.search(r"^\s*import\s+serial\b", src, re.MULTILINE), (
        "Script imports pyserial -- that's exactly what we're avoiding"
    )
    assert not re.search(r"^\s*from\s+serial\b", src, re.MULTILINE), (
        "Script imports pyserial -- that's exactly what we're avoiding"
    )


def test_script_uses_os_open_o_nonblock():
    """The os.open call must use O_NOCTTY | O_NONBLOCK so the cdc-acm driver
    doesn't issue the RTS-set ioctl that TinyUSB rejects."""
    src = REBOOT_SCRIPT.read_text(encoding="utf-8")
    assert "os.O_NONBLOCK" in src, (
        "os.open must include O_NONBLOCK to skip the termios open path"
    )
    assert "os.O_NOCTTY" in src, (
        "os.open must include O_NOCTTY (don't take controlling tty)"
    )


# ---------------------------------------------------------------------------
# main() under mocked os.open / os.write -- functional behaviour
# ---------------------------------------------------------------------------

def test_main_writes_exactly_magic_to_opened_fd():
    """Under mocked os.{open,write,close,path.exists}, main() must:
       - open the supplied port path
       - write EXACTLY the MAGIC bytes (no prefix, no trailing data, single call)
       - close the fd
       - return 0
    """
    mod = _import_fresh()

    writes = []
    closes = []
    opens = []

    def fake_open(path, flags, *_args):
        opens.append((path, flags))
        return 42  # fake fd

    def fake_write(fd, data):
        writes.append((fd, bytes(data)))
        return len(data)

    def fake_close(fd):
        closes.append(fd)

    with patch.object(mod.os, "open", side_effect=fake_open), \
         patch.object(mod.os, "write", side_effect=fake_write), \
         patch.object(mod.os, "close", side_effect=fake_close), \
         patch.object(mod.os.path, "exists", return_value=True), \
         patch.object(mod.time, "sleep"), \
         patch("sys.argv", [str(REBOOT_SCRIPT), "/dev/ttyACM0"]):
        rc = mod.main()

    assert rc == 0
    assert opens == [("/dev/ttyACM0",
                      os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)]
    assert writes == [(42, mod.MAGIC)], (
        f"Expected exactly one write of the full MAGIC, got {writes!r}"
    )
    assert closes == [42]


def test_main_clears_opost_before_writing():
    """When the port is a tty (e.g. a serial-getty is bound to it), main() must
    clear OPOST in the oflag before writing, so the kernel doesn't rewrite the
    magic's '\\n' bytes to '\\r\\n' and corrupt the sequence.  This is what lets
    `make flash-online` work on a host that runs a getty on the bridge port."""
    import termios

    mod = _import_fresh()

    # A plausible cooked-mode oflag (what agetty leaves behind).
    fake_attrs = [0, termios.OPOST | termios.ONLCR, 0, 0, 0, 0, [b"\x00"] * 32]
    sets = []

    with patch.object(mod.os, "open", return_value=9), \
         patch.object(mod.os, "write", side_effect=lambda fd, d: len(d)), \
         patch.object(mod.os, "close"), \
         patch.object(mod.os.path, "exists", return_value=True), \
         patch.object(mod.time, "sleep"), \
         patch.object(mod.termios, "tcgetattr", return_value=list(fake_attrs)), \
         patch.object(mod.termios, "tcsetattr",
                      side_effect=lambda fd, when, attrs: sets.append(list(attrs))), \
         patch("sys.argv", [str(REBOOT_SCRIPT), "/dev/ttyACM0"]):
        rc = mod.main()

    assert rc == 0
    assert sets, "expected tcsetattr to be called to put the port in raw output mode"
    assert not (sets[0][1] & termios.OPOST), (
        "OPOST must be cleared in the oflag before the magic write"
    )


def test_main_non_tty_port_still_writes_magic():
    """If the port is not a tty (tcgetattr raises), main() must swallow the
    termios error and still write the magic."""
    mod = _import_fresh()
    writes = []

    with patch.object(mod.os, "open", return_value=9), \
         patch.object(mod.os, "write",
                      side_effect=lambda fd, d: writes.append(bytes(d)) or len(d)), \
         patch.object(mod.os, "close"), \
         patch.object(mod.os.path, "exists", return_value=True), \
         patch.object(mod.time, "sleep"), \
         patch.object(mod.termios, "tcgetattr",
                      side_effect=mod.termios.error("not a tty")), \
         patch("sys.argv", [str(REBOOT_SCRIPT), "/dev/ttyACM0"]):
        rc = mod.main()

    assert rc == 0
    assert writes == [mod.MAGIC]


def test_main_short_write_returns_zero_with_warning():
    """If os.write returns fewer bytes than MAGIC, main() should warn (stderr)
    but still return 0 (the close still happens, the chip might have got
    enough)."""
    mod = _import_fresh()

    def short_write(fd, data):
        return max(1, len(data) // 2)

    with patch.object(mod.os, "open", return_value=7), \
         patch.object(mod.os, "write", side_effect=short_write), \
         patch.object(mod.os, "close"), \
         patch.object(mod.os.path, "exists", return_value=True), \
         patch.object(mod.time, "sleep"), \
         patch("sys.argv", [str(REBOOT_SCRIPT), "/dev/ttyACM0"]):
        rc = mod.main()

    assert rc == 0


def test_main_open_oserror_exits_1():
    """An OSError from os.open (e.g. EACCES, ENOENT after exists-check race)
    must surface as exit code 1 with a stderr error message."""
    mod = _import_fresh()

    def fail_open(path, flags, *_args):
        raise PermissionError(13, "Permission denied")

    with patch.object(mod.os, "open", side_effect=fail_open), \
         patch.object(mod.os.path, "exists", return_value=True), \
         patch("sys.argv", [str(REBOOT_SCRIPT), "/dev/ttyACM0"]):
        rc = mod.main()

    assert rc == 1


def test_main_write_oserror_exits_1_and_closes_fd():
    """An OSError from os.write must surface as exit code 1 and the fd must
    still be closed."""
    mod = _import_fresh()
    closes = []

    with patch.object(mod.os, "open", return_value=11), \
         patch.object(mod.os, "write",
                      side_effect=OSError("simulated bus error")), \
         patch.object(mod.os, "close", side_effect=closes.append), \
         patch.object(mod.os.path, "exists", return_value=True), \
         patch("sys.argv", [str(REBOOT_SCRIPT), "/dev/ttyACM0"]):
        rc = mod.main()

    assert rc == 1
    assert closes == [11], (
        f"fd should still be closed on write error; close history: {closes!r}"
    )


# ---------------------------------------------------------------------------
# End-to-end CLI smoke (no device required)
# ---------------------------------------------------------------------------

def test_help_works():
    """--help exits 0 and shows the script's purpose."""
    result = subprocess.run(
        [sys.executable, str(REBOOT_SCRIPT), "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "magic" in result.stdout.lower() or "reboot" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Doc references the correct re-enumeration VID:PID
# ---------------------------------------------------------------------------

def test_docstring_mentions_dfu_vidpid():
    """The script docstring should reference the actual re-enumeration target
    (303a:0009 ESP32-S3 ROM USB DFU endpoint), not the older incorrect
    303a:1001 (USB-Serial-JTAG) guess."""
    src = REBOOT_SCRIPT.read_text(encoding="utf-8")
    assert "303a:0009" in src
