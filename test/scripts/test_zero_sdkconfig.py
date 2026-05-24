#!/usr/bin/env python3
"""
test/scripts/test_zero_sdkconfig.py
-- Structural assertions for sdkconfig.zero.defaults (Zero-stability settings).

Verifies that sdkconfig.zero.defaults contains each required Zero-stability
setting with the correct value.  These tests act as regression guards: if
someone accidentally removes or changes a critical override, the tests catch it
before a Zero build is flashed with broken behaviour.

Critical setting: CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=n MUST NOT be y.
When y, WiFi RX buffers land in PSRAM, which is too slow for the WiFi ISR
under high RX rates (TLS handshake fragments), causing ppRxFragmentProc panics.

Also validates that sdkconfig.defaults still carries CONFIG_LWIP_SNTP_MAX_SERVERS=4
(regression guard for the prior NTP fix).
"""

import os
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

ZERO_DEFAULTS    = os.path.join(PROJECT_DIR, "sdkconfig.zero.defaults")
GLOBAL_DEFAULTS  = os.path.join(PROJECT_DIR, "sdkconfig.defaults")


def _read(path):
    with open(path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------

def test_zero_defaults_file_exists():
    """sdkconfig.zero.defaults exists in the project root."""
    assert os.path.isfile(ZERO_DEFAULTS), \
        f"sdkconfig.zero.defaults not found at {ZERO_DEFAULTS}"


def test_global_defaults_file_exists():
    """sdkconfig.defaults exists in the project root."""
    assert os.path.isfile(GLOBAL_DEFAULTS), \
        f"sdkconfig.defaults not found at {GLOBAL_DEFAULTS}"


# ---------------------------------------------------------------------------
# CRITICAL: SPIRAM_TRY_ALLOCATE_WIFI_LWIP must be n
# ---------------------------------------------------------------------------

def test_spiram_try_allocate_wifi_lwip_is_n():
    """CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=n is set (CRITICAL: y breaks WiFi)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=n" in src, (
        "CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=n not found in sdkconfig.zero.defaults. "
        "This flag MUST be n -- setting it to y puts WiFi RX buffers in slow PSRAM "
        "and causes ppRxFragmentProc panics under TLS handshake load."
    )


def test_spiram_try_allocate_wifi_lwip_not_y():
    """CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y does NOT appear (crash guard)."""
    src = _read(ZERO_DEFAULTS)
    # Check that the dangerous 'y' form is not present (comments excluded by
    # checking only non-comment lines).
    non_comment_lines = [
        line for line in src.splitlines()
        if not line.strip().startswith("#")
    ]
    dangerous = [
        line for line in non_comment_lines
        if "CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y" in line
    ]
    assert not dangerous, (
        f"CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=y found on non-comment line(s): "
        f"{dangerous}. This causes ppRxFragmentProc crashes -- must be n."
    )


# ---------------------------------------------------------------------------
# PSRAM heap routing settings
# ---------------------------------------------------------------------------

def test_spiram_use_malloc_enabled():
    """CONFIG_SPIRAM_USE_MALLOC=y routes most allocations to PSRAM."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPIRAM_USE_MALLOC=y" in src, \
        "CONFIG_SPIRAM_USE_MALLOC=y not found in sdkconfig.zero.defaults"


def test_spiram_malloc_alwaysinternal_is_small():
    """CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL is set to a small value (<=256)."""
    src = _read(ZERO_DEFAULTS)
    m = re.search(r"^CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=(\d+)", src, re.MULTILINE)
    assert m, \
        "CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL not found in sdkconfig.zero.defaults"
    value = int(m.group(1))
    assert value <= 256, (
        f"CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL={value} -- expected <=256. "
        "A larger threshold routes more allocations to internal RAM, defeating "
        "the PSRAM workaround for the v0.2 spinlock CAS hang."
    )
    assert value == 256, (
        f"CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL={value} -- expected exactly 256. "
        "Changing this value should be intentional; update this test if so."
    )


# ---------------------------------------------------------------------------
# Wi-Fi AMPDU and PM stability settings
# ---------------------------------------------------------------------------

def test_ampdu_rx_disabled():
    """CONFIG_ESP_WIFI_AMPDU_RX_ENABLED=n disables A-MPDU RX aggregation."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_AMPDU_RX_ENABLED=n" in src, \
        "CONFIG_ESP_WIFI_AMPDU_RX_ENABLED=n not found in sdkconfig.zero.defaults"


def test_ampdu_tx_disabled():
    """CONFIG_ESP_WIFI_AMPDU_TX_ENABLED=n disables A-MPDU TX aggregation."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_AMPDU_TX_ENABLED=n" in src, \
        "CONFIG_ESP_WIFI_AMPDU_TX_ENABLED=n not found in sdkconfig.zero.defaults"


def test_pm_enable_is_n():
    """CONFIG_PM_ENABLE=n disables CPU power management (avoids beacon-wake race)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_PM_ENABLE=n" in src, \
        "CONFIG_PM_ENABLE=n not found in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# IRAM optimisations
# ---------------------------------------------------------------------------

def test_wifi_extra_iram_opt_enabled():
    """CONFIG_ESP_WIFI_EXTRA_IRAM_OPT=y keeps WiFi RX paths in IRAM."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_EXTRA_IRAM_OPT=y" in src, \
        "CONFIG_ESP_WIFI_EXTRA_IRAM_OPT=y not found in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# Stack overflow detection
# ---------------------------------------------------------------------------

def test_stackoverflow_canary_enabled():
    """CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y enables canary-word detection."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y" in src, \
        "CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y not found in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# PSRAM hardware mode (Zero has Quad, not Octal)
# ---------------------------------------------------------------------------

def test_spiram_mode_quad_enabled():
    """CONFIG_SPIRAM_MODE_QUAD=y selects Quad PSRAM mode (Zero has 2 MB QSPI)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPIRAM_MODE_QUAD=y" in src, \
        "CONFIG_SPIRAM_MODE_QUAD=y not found in sdkconfig.zero.defaults"


def test_spiram_mode_oct_disabled():
    """CONFIG_SPIRAM_MODE_OCT=n overrides the DevKit's Octal PSRAM mode."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPIRAM_MODE_OCT=n" in src, \
        "CONFIG_SPIRAM_MODE_OCT=n not found in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# Flash size (Zero has 4 MB, not 16 MB)
# ---------------------------------------------------------------------------

def test_flash_size_4mb_enabled():
    """CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y selects 4 MB flash (Zero has 4 MB)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y" in src, \
        "CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y not found in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# WiFi RX buffer pool (larger pool for TLS handshake burst tolerance)
# ---------------------------------------------------------------------------

def test_wifi_static_rx_buffer_num():
    """CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=16 is set."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=16" in src, \
        "CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=16 not found in sdkconfig.zero.defaults"


def test_wifi_dynamic_rx_buffer_num():
    """CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=64 is set."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=64" in src, \
        "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=64 not found in sdkconfig.zero.defaults"


def test_wifi_rx_ba_win():
    """CONFIG_ESP_WIFI_RX_BA_WIN=16 sets the Block Ack RX window size."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_RX_BA_WIN=16" in src, \
        "CONFIG_ESP_WIFI_RX_BA_WIN=16 not found in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# Partition table override (Zero uses partitions_zero.csv)
# ---------------------------------------------------------------------------

def test_zero_custom_partition_table():
    """sdkconfig.zero.defaults sets CONFIG_PARTITION_TABLE_CUSTOM=y."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_PARTITION_TABLE_CUSTOM=y" in src, \
        "CONFIG_PARTITION_TABLE_CUSTOM=y not found in sdkconfig.zero.defaults"


def test_zero_custom_partition_filename():
    """sdkconfig.zero.defaults points to partitions_zero.csv."""
    src = _read(ZERO_DEFAULTS)
    assert "partitions_zero.csv" in src, \
        "partitions_zero.csv not referenced in sdkconfig.zero.defaults"


# ---------------------------------------------------------------------------
# Sanity check: sdkconfig.defaults (global) must still carry NTP max servers
# ---------------------------------------------------------------------------

def test_global_defaults_lwip_sntp_max_servers():
    """sdkconfig.defaults still sets CONFIG_LWIP_SNTP_MAX_SERVERS=4 (NTP regression guard)."""
    src = _read(GLOBAL_DEFAULTS)
    assert "CONFIG_LWIP_SNTP_MAX_SERVERS=4" in src, (
        "CONFIG_LWIP_SNTP_MAX_SERVERS=4 not found in sdkconfig.defaults. "
        "This was a prior fix for NTP with multiple servers -- do not remove it."
    )
