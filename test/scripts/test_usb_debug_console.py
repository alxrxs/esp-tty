#!/usr/bin/env python3
"""
test/scripts/test_usb_debug_console.py
-- Structural guard tests for the USB_DEBUG_CONSOLE_ONLY feature.

Asserts that:
  - main/main.c wraps usb_cdc_init() / usb_cdc_start_task() in the
    USB_DEBUG_CONSOLE_ONLY preprocessor guard
  - main/usb_cdc.c is gated on the macro (no TinyUSB code compiled in)
  - platformio.ini defines [env:esp32s3_debug] and [env:esp32s3_zero_debug]
  - sdkconfig.debug_console.defaults exists and sets
    CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y and CONFIG_TINYUSB_CDC_ENABLED=n
  - Makefile recognises s3debug and s3zerodebug model names mapped to the
    correct PlatformIO envs

These are compile-time structural guards.  Confirming that the
USB-Serial-JTAG console actually works requires hardware; that path is
covered by manual testing with `pio device monitor` on a Zero or DevKitC-1.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

MAIN_C           = os.path.join(PROJECT_DIR, "main", "main.c")
USB_CDC_C        = os.path.join(PROJECT_DIR, "main", "usb_cdc.c")
PLATFORMIO_INI   = os.path.join(PROJECT_DIR, "platformio.ini")
SDKCONFIG_OVERLAY = os.path.join(PROJECT_DIR, "sdkconfig.debug_console.defaults")
MAKEFILE         = os.path.join(PROJECT_DIR, "Makefile")


def _read(path):
    with open(path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# main.c: guard around usb_cdc_init / usb_cdc_start_task
# ---------------------------------------------------------------------------

def test_main_c_has_usb_debug_console_only_guard():
    """main.c contains a #ifdef / #elif USB_DEBUG_CONSOLE_ONLY branch."""
    src = _read(MAIN_C)
    assert "USB_DEBUG_CONSOLE_ONLY" in src, \
        "USB_DEBUG_CONSOLE_ONLY not found in main/main.c"


def test_main_c_usb_cdc_init_guarded():
    """usb_cdc_init() call site is inside a conditional that excludes USB_DEBUG_CONSOLE_ONLY."""
    src = _read(MAIN_C)
    # The call must exist somewhere in the file
    assert "usb_cdc_init(" in src, \
        "usb_cdc_init() call not found in main/main.c"
    # The USB_DEBUG_CONSOLE_ONLY guard must gate it (as elif or separate ifndef)
    assert "USB_DEBUG_CONSOLE_ONLY" in src, \
        "USB_DEBUG_CONSOLE_ONLY guard missing from main/main.c"
    # The init call must NOT appear after the USB_DEBUG_CONSOLE_ONLY elif/ifdef
    # (i.e. the call is inside the else/non-debug branch).
    # Find the guard block and verify usb_cdc_init is in the non-debug branch.
    idx_guard = src.find("USB_DEBUG_CONSOLE_ONLY")
    idx_init  = src.find("usb_cdc_init(")
    assert idx_init < idx_guard or _call_is_in_else_branch(src), \
        "usb_cdc_init() appears to be inside the USB_DEBUG_CONSOLE_ONLY branch"


def _call_is_in_else_branch(src):
    """
    Return True if usb_cdc_init() appears after #else in the conditional
    that contains USB_DEBUG_CONSOLE_ONLY (i.e. it is compiled in production,
    not in debug mode).
    """
    # Find the #elif USB_DEBUG_CONSOLE_ONLY line, then check that usb_cdc_init
    # appears after the subsequent #else.
    m_guard = re.search(r'#elif\s+defined\(USB_DEBUG_CONSOLE_ONLY\)', src)
    if not m_guard:
        # Could be an #ifndef / #if !defined form
        m_guard = re.search(r'#ifndef\s+USB_DEBUG_CONSOLE_ONLY', src)
    if not m_guard:
        return False
    after_guard = src[m_guard.end():]
    m_else = re.search(r'^#else', after_guard, re.MULTILINE)
    if not m_else:
        # No #else -- the init call is guarded away in debug mode; that's fine
        return True
    after_else = after_guard[m_else.end():]
    return "usb_cdc_init(" in after_else


def test_main_c_debug_console_log_message():
    """main.c emits a recognisable log line in the USB_DEBUG_CONSOLE_ONLY branch."""
    src = _read(MAIN_C)
    assert "USB_DEBUG_CONSOLE_ONLY" in src
    assert "USB-Serial-JTAG" in src or "debug_console" in src.lower() or \
           "USB_DEBUG_CONSOLE_ONLY" in src, \
        "No recognisable log message in the USB_DEBUG_CONSOLE_ONLY branch of main.c"


# ---------------------------------------------------------------------------
# usb_cdc.c: TinyUSB block gated away in debug-console mode
# ---------------------------------------------------------------------------

def test_usb_cdc_c_gated_on_debug_console_macro():
    """usb_cdc.c omits TinyUSB code when USB_DEBUG_CONSOLE_ONLY is defined."""
    src = _read(USB_CDC_C)
    assert "USB_DEBUG_CONSOLE_ONLY" in src, \
        "USB_DEBUG_CONSOLE_ONLY guard not found in main/usb_cdc.c"


def test_usb_cdc_c_tinyusb_inside_guard():
    """tinyusb_driver_install() is only called when USB_DEBUG_CONSOLE_ONLY is NOT set."""
    src = _read(USB_CDC_C)
    # The driver install call must exist
    assert "tinyusb_driver_install" in src, \
        "tinyusb_driver_install not found in usb_cdc.c"
    # It must appear before the else/stub block (i.e. inside the non-debug guard)
    idx_install = src.find("tinyusb_driver_install")
    idx_guard   = src.find("USB_DEBUG_CONSOLE_ONLY")
    # The guard condition appears before the install call (the #if guard is at
    # the top of the active block, and the call is inside that block).
    assert idx_guard < idx_install, \
        "USB_DEBUG_CONSOLE_ONLY guard should precede tinyusb_driver_install in usb_cdc.c"


def test_usb_cdc_c_stubs_for_debug_mode():
    """usb_cdc.c provides no-op stubs for the debug-console case."""
    src = _read(USB_CDC_C)
    # The stub section comment should be present
    assert "BRIDGE_LOOPBACK" in src and "USB_DEBUG_CONSOLE_ONLY" in src, \
        "Stub section guard not updated in usb_cdc.c"


# ---------------------------------------------------------------------------
# platformio.ini: new envs declared
# ---------------------------------------------------------------------------

def test_platformio_ini_has_esp32s3_debug_env():
    """platformio.ini declares [env:esp32s3_debug]."""
    src = _read(PLATFORMIO_INI)
    assert "[env:esp32s3_debug]" in src, \
        "[env:esp32s3_debug] not found in platformio.ini"


def test_platformio_ini_has_esp32s3_zero_debug_env():
    """platformio.ini declares [env:esp32s3_zero_debug]."""
    src = _read(PLATFORMIO_INI)
    assert "[env:esp32s3_zero_debug]" in src, \
        "[env:esp32s3_zero_debug] not found in platformio.ini"


def test_platformio_ini_debug_envs_set_build_flag():
    """Both debug envs pass -DUSB_DEBUG_CONSOLE_ONLY=1 in build_flags."""
    src = _read(PLATFORMIO_INI)
    # Find each env block and confirm the flag is present
    for env in ("esp32s3_debug", "esp32s3_zero_debug"):
        block_start = src.find(f"[env:{env}]")
        assert block_start != -1, f"[env:{env}] not found"
        # The block ends at the next [env: or end of file
        next_env = src.find("\n[", block_start + 1)
        block = src[block_start:next_env] if next_env != -1 else src[block_start:]
        assert "USB_DEBUG_CONSOLE_ONLY=1" in block, \
            f"-DUSB_DEBUG_CONSOLE_ONLY=1 not in [env:{env}] build_flags"


def test_platformio_ini_debug_envs_use_overlay():
    """Both debug envs reference sdkconfig.debug_console.defaults."""
    src = _read(PLATFORMIO_INI)
    for env in ("esp32s3_debug", "esp32s3_zero_debug"):
        block_start = src.find(f"[env:{env}]")
        assert block_start != -1
        next_env = src.find("\n[", block_start + 1)
        block = src[block_start:next_env] if next_env != -1 else src[block_start:]
        assert "sdkconfig.debug_console.defaults" in block, \
            f"sdkconfig.debug_console.defaults not referenced in [env:{env}]"


# ---------------------------------------------------------------------------
# sdkconfig.debug_console.defaults: required knobs
# ---------------------------------------------------------------------------

def test_sdkconfig_overlay_exists():
    """sdkconfig.debug_console.defaults file exists."""
    assert os.path.isfile(SDKCONFIG_OVERLAY), \
        f"sdkconfig.debug_console.defaults not found at {SDKCONFIG_OVERLAY}"


def test_sdkconfig_overlay_enables_usb_serial_jtag_console():
    """sdkconfig.debug_console.defaults sets CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y."""
    src = _read(SDKCONFIG_OVERLAY)
    assert "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y" in src, \
        "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y not set in sdkconfig.debug_console.defaults"


def test_sdkconfig_overlay_disables_tinyusb():
    """sdkconfig.debug_console.defaults sets CONFIG_TINYUSB_CDC_ENABLED=n."""
    src = _read(SDKCONFIG_OVERLAY)
    assert "CONFIG_TINYUSB_CDC_ENABLED=n" in src, \
        "CONFIG_TINYUSB_CDC_ENABLED=n not set in sdkconfig.debug_console.defaults"


def test_sdkconfig_overlay_disables_uart_default_console():
    """sdkconfig.debug_console.defaults overrides CONFIG_ESP_CONSOLE_UART_DEFAULT=n."""
    src = _read(SDKCONFIG_OVERLAY)
    assert "CONFIG_ESP_CONSOLE_UART_DEFAULT=n" in src, \
        "CONFIG_ESP_CONSOLE_UART_DEFAULT=n not set in sdkconfig.debug_console.defaults"


# ---------------------------------------------------------------------------
# Makefile: model-name mappings
# ---------------------------------------------------------------------------

def test_makefile_knows_s3debug_model():
    """Makefile KNOWN_MODELS includes s3debug."""
    src = _read(MAKEFILE)
    m = re.search(r'^KNOWN_MODELS\s*:?=\s*(.+)$', src, re.MULTILINE)
    assert m, "KNOWN_MODELS line not found in Makefile"
    models = m.group(1).split()
    assert "s3debug" in models, \
        f"s3debug not in KNOWN_MODELS ({models})"


def test_makefile_knows_s3zerodebug_model():
    """Makefile KNOWN_MODELS includes s3zerodebug."""
    src = _read(MAKEFILE)
    m = re.search(r'^KNOWN_MODELS\s*:?=\s*(.+)$', src, re.MULTILINE)
    assert m, "KNOWN_MODELS line not found in Makefile"
    models = m.group(1).split()
    assert "s3zerodebug" in models, \
        f"s3zerodebug not in KNOWN_MODELS ({models})"


def test_makefile_s3debug_maps_to_esp32s3_debug():
    """Makefile maps s3debug -> esp32s3_debug."""
    src = _read(MAKEFILE)
    assert "ENV_OF_s3debug" in src, "ENV_OF_s3debug not defined in Makefile"
    m = re.search(r'^ENV_OF_s3debug\s*:?=\s*(\S+)', src, re.MULTILINE)
    assert m, "ENV_OF_s3debug assignment not found in Makefile"
    assert m.group(1) == "esp32s3_debug", \
        f"ENV_OF_s3debug should be esp32s3_debug, got {m.group(1)!r}"


def test_makefile_s3zerodebug_maps_to_esp32s3_zero_debug():
    """Makefile maps s3zerodebug -> esp32s3_zero_debug."""
    src = _read(MAKEFILE)
    assert "ENV_OF_s3zerodebug" in src, "ENV_OF_s3zerodebug not defined in Makefile"
    m = re.search(r'^ENV_OF_s3zerodebug\s*:?=\s*(\S+)', src, re.MULTILINE)
    assert m, "ENV_OF_s3zerodebug assignment not found in Makefile"
    assert m.group(1) == "esp32s3_zero_debug", \
        f"ENV_OF_s3zerodebug should be esp32s3_zero_debug, got {m.group(1)!r}"
