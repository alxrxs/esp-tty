#!/usr/bin/env python3
"""
test/scripts/test_reboot_to_bootloader.py
-- Tests for scripts/reboot_to_bootloader.py

Covers:
  - MAGIC byte sequence matches lib/usb_cdc_boot_trigger/usb_cdc_boot_trigger.c
  - CLI error paths (missing port arg, non-existent port, pyserial not installed)
  - RTS/DTR deassertion (mock serial.Serial)
  - Writes exactly one MAGIC, flushes, closes
  - --baud override is accepted
  - Exit codes 0/1/2 are correct
"""

import importlib
import os
import sys
import re
import subprocess
import types
import unittest
from unittest.mock import MagicMock, call, patch

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
REBOOT_SCRIPT = os.path.join(PROJECT_DIR, "scripts", "reboot_to_bootloader.py")
BOOT_TRIGGER_C = os.path.join(PROJECT_DIR, "lib", "usb_cdc_boot_trigger",
                               "usb_cdc_boot_trigger.c")

sys.path.insert(0, os.path.join(PROJECT_DIR, "scripts"))


def _import_fresh():
    """Import reboot_to_bootloader with a clean module cache entry."""
    if "reboot_to_bootloader" in sys.modules:
        del sys.modules["reboot_to_bootloader"]
    import reboot_to_bootloader as m
    return m


# ---------------------------------------------------------------------------
# 1. MAGIC byte sequence matches the C source
# ---------------------------------------------------------------------------

def test_magic_matches_c_source():
    """MAGIC in the Python script must be byte-for-byte identical to k_magic[] in C."""
    mod = _import_fresh()
    py_magic: bytes = mod.MAGIC

    with open(BOOT_TRIGGER_C) as f:
        c_src = f.read()

    # Extract the string literal from k_magic[] = "...";
    # The C source uses a raw string literal on one line.
    m = re.search(r'k_magic\[\]\s*=\s*"([^"]+)"', c_src)
    assert m, "Could not find k_magic[] string literal in usb_cdc_boot_trigger.c"

    # The C string literal uses escape sequences; decode them the same way C does.
    raw_literal = m.group(1)
    # Replace \n escape with actual newline (C only uses \n here)
    c_magic_str = raw_literal.replace(r"\n", "\n")
    c_magic: bytes = c_magic_str.encode("ascii")

    assert py_magic == c_magic, (
        f"MAGIC mismatch!\n"
        f"  Python : {py_magic!r}\n"
        f"  C src  : {c_magic!r}"
    )


def test_magic_starts_and_ends_with_newline():
    """MAGIC is bracketed by newlines (as the C comment states)."""
    mod = _import_fresh()
    assert mod.MAGIC[0:1] == b"\n", "MAGIC must start with a newline"
    assert mod.MAGIC[-1:] == b"\n", "MAGIC must end with a newline"


def test_magic_body_contains_no_newline():
    """The body of MAGIC (between the two bracket newlines) has no embedded newlines."""
    mod = _import_fresh()
    body = mod.MAGIC[1:-1]
    assert b"\n" not in body, f"MAGIC body must not contain newlines, got {body!r}"


# ---------------------------------------------------------------------------
# 2. --baud override accepted (argparse does not reject it)
# ---------------------------------------------------------------------------

def test_baud_override_accepted():
    """Passing --baud 9600 does not cause argparse to exit 2."""
    result = subprocess.run(
        [sys.executable, REBOOT_SCRIPT, "--help"],
        capture_output=True, text=True,
    )
    assert "--baud" in result.stdout, "--baud not advertised in --help output"


# ---------------------------------------------------------------------------
# 3. CLI exit codes: missing port -> exit 2 (argparse)
# ---------------------------------------------------------------------------

def test_missing_port_exits_2():
    """Running the script with no arguments must exit 2 (argparse usage error)."""
    result = subprocess.run(
        [sys.executable, REBOOT_SCRIPT],
        capture_output=True, text=True,
    )
    assert result.returncode == 2, (
        f"Expected exit code 2 for missing port, got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# 4. CLI exit code 1: non-existent port -> serial.SerialException -> exit 1
# ---------------------------------------------------------------------------

def test_nonexistent_port_exits_1():
    """Opening /dev/ttyNONEXISTENT must raise SerialException and return exit code 1."""
    result = subprocess.run(
        [sys.executable, REBOOT_SCRIPT, "/dev/ttyNONEXISTENT_esp_tty_test"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, (
        f"Expected exit code 1 for non-existent port, got {result.returncode}\n"
        f"stderr: {result.stderr}"
    )
    assert "error:" in result.stderr.lower() or "error" in result.stderr.lower(), (
        f"Expected error message on stderr, got: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# 5. CLI exit code 2: pyserial not installed branch
# ---------------------------------------------------------------------------

def test_pyserial_not_installed_exits_2():
    """If pyserial is not importable the script must print a helpful message and exit 2."""
    mod = _import_fresh()

    # Simulate the ImportError branch by calling main() with serial hidden
    import builtins
    real_import = builtins.__import__

    def _blocking_import(name, *args, **kwargs):
        if name == "serial":
            raise ImportError("No module named 'serial'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=_blocking_import):
        # Re-import to pick up the patched __import__
        if "reboot_to_bootloader" in sys.modules:
            del sys.modules["reboot_to_bootloader"]
        import reboot_to_bootloader as fresh_mod

        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = fresh_mod.main()

    assert rc == 2, f"Expected exit code 2 when pyserial missing, got {rc}"


# ---------------------------------------------------------------------------
# 6. RTS/DTR deassertion: mock serial.Serial
# ---------------------------------------------------------------------------

def _make_mock_serial():
    """Return a MagicMock that behaves like a serial.Serial instance."""
    mock_ser = MagicMock()
    mock_ser.__enter__ = MagicMock(return_value=mock_ser)
    mock_ser.__exit__ = MagicMock(return_value=False)
    return mock_ser


def test_setdtr_false_called():
    """main() must call ser.setDTR(False) before writing the magic."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = MagicMock(return_value=mock_ser)
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = mod.main()

    assert rc == 0, f"Expected exit 0, got {rc}"
    mock_ser.setDTR.assert_called_with(False)


def test_setrts_false_called():
    """main() must call ser.setRTS(False) before writing the magic."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = MagicMock(return_value=mock_ser)
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = mod.main()

    assert rc == 0
    mock_ser.setRTS.assert_called_with(False)


# ---------------------------------------------------------------------------
# 7. Writes EXACTLY one MAGIC, flushes, closes
# ---------------------------------------------------------------------------

def test_writes_exactly_one_magic():
    """main() must call ser.write() exactly once with the full MAGIC bytes."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = MagicMock(return_value=mock_ser)
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = mod.main()

    assert rc == 0
    write_calls = mock_ser.write.call_args_list
    assert len(write_calls) == 1, (
        f"Expected exactly 1 write() call, got {len(write_calls)}: {write_calls}"
    )
    written = write_calls[0].args[0]
    assert written == mod.MAGIC, (
        f"write() called with {written!r}, expected {mod.MAGIC!r}"
    )


def test_flush_called_after_write():
    """main() must call ser.flush() after ser.write()."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()
    call_order = []
    mock_ser.write.side_effect   = lambda *a, **kw: call_order.append("write")
    mock_ser.flush.side_effect   = lambda *a, **kw: call_order.append("flush")

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = MagicMock(return_value=mock_ser)
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = mod.main()

    assert rc == 0
    assert "write" in call_order, "write() not called"
    assert "flush" in call_order, "flush() not called"
    assert call_order.index("write") < call_order.index("flush"), \
        "flush() must be called after write()"


def test_close_called():
    """main() must call ser.close() to release the port."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = MagicMock(return_value=mock_ser)
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = mod.main()

    assert rc == 0
    mock_ser.close.assert_called_once()


# ---------------------------------------------------------------------------
# 8. --baud flag is forwarded to serial.Serial constructor
# ---------------------------------------------------------------------------

def test_baud_override_forwarded_to_serial():
    """--baud 9600 must be passed as the baud_rate argument to serial.Serial."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()
    captured = {}

    def fake_serial_constructor(port, baud, **kwargs):
        captured["port"] = port
        captured["baud"] = baud
        return mock_ser

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = fake_serial_constructor
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0", "--baud", "9600"]):
            rc = mod.main()

    assert rc == 0
    assert captured.get("baud") == 9600, \
        f"Expected baud=9600, got baud={captured.get('baud')!r}"


# ---------------------------------------------------------------------------
# 9. Exit code 0 on success
# ---------------------------------------------------------------------------

def test_exit_code_0_on_success():
    """main() returns 0 when the port opens and the magic is sent successfully."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = MagicMock(return_value=mock_ser)
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            rc = mod.main()

    assert rc == 0, f"Expected exit code 0 on success, got {rc}"


# ---------------------------------------------------------------------------
# 10. rtscts=False and dsrdtr=False passed to serial.Serial
# ---------------------------------------------------------------------------

def test_rtscts_dsrdtr_disabled():
    """serial.Serial must be called with rtscts=False and dsrdtr=False."""
    mod = _import_fresh()
    mock_ser = _make_mock_serial()
    captured_kwargs = {}

    def fake_serial_constructor(port, baud, **kwargs):
        captured_kwargs.update(kwargs)
        return mock_ser

    mock_serial_module = types.ModuleType("serial")
    mock_serial_module.Serial = fake_serial_constructor
    mock_serial_module.SerialException = OSError

    with patch.dict(sys.modules, {"serial": mock_serial_module}):
        with patch("sys.argv", [REBOOT_SCRIPT, "/dev/ttyACM0"]):
            mod.main()

    assert captured_kwargs.get("rtscts") is False, \
        f"Expected rtscts=False, got {captured_kwargs.get('rtscts')!r}"
    assert captured_kwargs.get("dsrdtr") is False, \
        f"Expected dsrdtr=False, got {captured_kwargs.get('dsrdtr')!r}"
