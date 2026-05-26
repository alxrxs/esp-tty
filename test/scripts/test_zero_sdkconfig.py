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


# ---------------------------------------------------------------------------
# New: sdkconfig invariant matrix -- Wi-Fi/PSRAM/RX-buf related options
# ---------------------------------------------------------------------------

def test_spiram_malloc_alwaysinternal_is_positive():
    """CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL must be > 0 (zero would break the workaround)."""
    src = _read(ZERO_DEFAULTS)
    m = re.search(r"^CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=(\d+)", src, re.MULTILINE)
    assert m, "CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL not found in sdkconfig.zero.defaults"
    value = int(m.group(1))
    assert value > 0, (
        f"CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL={value} -- must be > 0. "
        "Zero means all small allocations go to PSRAM, bypassing the spinlock "
        "workaround for allocations that must stay internal."
    )


def test_wifi_static_rx_buffer_num_minimum():
    """CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM is at least 10 (baseline) and at most 64."""
    src = _read(ZERO_DEFAULTS)
    m = re.search(r"^CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM=(\d+)", src, re.MULTILINE)
    assert m, "CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM not found in sdkconfig.zero.defaults"
    value = int(m.group(1))
    assert value >= 10, (
        f"CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM={value} is below the ESP-IDF "
        "minimum safe value of 10 for TLS workloads."
    )
    assert value <= 64, (
        f"CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM={value} is unusually large (>64). "
        "Each buffer costs ~1600 B of internal RAM -- verify this is intentional."
    )


def test_wifi_dynamic_rx_buffer_num_minimum():
    """CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM is at least 32 and at most 128."""
    src = _read(ZERO_DEFAULTS)
    m = re.search(r"^CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM=(\d+)", src, re.MULTILINE)
    assert m, "CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM not found in sdkconfig.zero.defaults"
    value = int(m.group(1))
    assert value >= 32, (
        f"CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM={value} is below 32. "
        "Under TLS burst load on the Zero the buffer pool depletes and "
        "ppRxFragmentProc panics."
    )
    assert value <= 128, (
        f"CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM={value} is unusually large (>128). "
        "Verify that the internal RAM budget can accommodate this."
    )


def test_pm_enable_not_y():
    """CONFIG_PM_ENABLE=y must NOT appear (regression guard -- y causes beacon-wake race)."""
    src = _read(ZERO_DEFAULTS)
    non_comment_lines = [
        line for line in src.splitlines()
        if not line.strip().startswith("#")
    ]
    dangerous = [
        line for line in non_comment_lines
        if "CONFIG_PM_ENABLE=y" in line
    ]
    assert not dangerous, (
        "CONFIG_PM_ENABLE=y found on a non-comment line in sdkconfig.zero.defaults. "
        "Power management must stay off on Zero silicon to avoid modem-sleep beacon "
        "timing races."
    )


def test_spiram_try_allocate_wifi_lwip_not_absent():
    """CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP is explicitly set (not silently omitted)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP" in src, (
        "CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP is entirely absent from "
        "sdkconfig.zero.defaults. It must be explicitly set to =n so a future "
        "sdkconfig.defaults change cannot accidentally enable it."
    )


def test_wifi_slp_iram_opt_enabled():
    """CONFIG_ESP_WIFI_SLP_IRAM_OPT=y keeps WiFi sleep paths in IRAM (Zero CACHE-126 fix)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_ESP_WIFI_SLP_IRAM_OPT=y" in src, (
        "CONFIG_ESP_WIFI_SLP_IRAM_OPT=y not found in sdkconfig.zero.defaults. "
        "This is required alongside EXTRA_IRAM_OPT to prevent the CACHE-126 "
        "panic on FH4R2 v0.2 silicon."
    )


def test_esp_int_wdt_timeout_ms_present_and_elevated():
    """CONFIG_ESP_INT_WDT_TIMEOUT_MS is present and greater than the default 300 ms."""
    src = _read(ZERO_DEFAULTS)
    m = re.search(r"^CONFIG_ESP_INT_WDT_TIMEOUT_MS=(\d+)", src, re.MULTILINE)
    assert m, (
        "CONFIG_ESP_INT_WDT_TIMEOUT_MS not found in sdkconfig.zero.defaults. "
        "This must be set higher than the default 300 ms to avoid WDT fires "
        "during transient spinlock contention on Zero silicon."
    )
    value = int(m.group(1))
    assert value > 300, (
        f"CONFIG_ESP_INT_WDT_TIMEOUT_MS={value} -- expected > 300 (the ESP-IDF default). "
        "A low timeout fires the WDT during spinlock contention on Zero v0.2 silicon."
    )


def test_spi_flash_auto_suspend_enabled():
    """CONFIG_SPI_FLASH_AUTO_SUSPEND=y is present (reduces CAS contention with flash reads)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPI_FLASH_AUTO_SUSPEND=y" in src, (
        "CONFIG_SPI_FLASH_AUTO_SUSPEND=y not found in sdkconfig.zero.defaults. "
        "This mitigates CAS spinlock contention that causes WDT fires on Zero "
        "when flash reads coincide with lock-held critical sections."
    )


def test_zero_defaults_has_no_duplicate_keys():
    """sdkconfig.zero.defaults has no CONFIG_ key defined more than once."""
    src = _read(ZERO_DEFAULTS)
    keys = []
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        m = re.match(r"^(CONFIG_[A-Z0-9_]+)=", stripped)
        if m:
            keys.append(m.group(1))
    seen = {}
    dupes = []
    for k in keys:
        seen[k] = seen.get(k, 0) + 1
    dupes = [k for k, count in seen.items() if count > 1]
    assert not dupes, (
        f"Duplicate CONFIG_ keys in sdkconfig.zero.defaults: {dupes}. "
        "Duplicate keys can cause unpredictable behaviour depending on which "
        "kconfig parser processes them last."
    )


def test_spiram_type_auto_enabled():
    """CONFIG_SPIRAM_TYPE_AUTO=y is present (auto-detects the embedded 2 MB QSPI part)."""
    src = _read(ZERO_DEFAULTS)
    assert "CONFIG_SPIRAM_TYPE_AUTO=y" in src, (
        "CONFIG_SPIRAM_TYPE_AUTO=y not found in sdkconfig.zero.defaults. "
        "The Zero FH4R2 uses an embedded QSPI PSRAM whose exact part varies by "
        "batch; auto-detect must be enabled."
    )


# ---------------------------------------------------------------------------
# New: platformio.ini Zero env build flags
# ---------------------------------------------------------------------------

PLATFORMIO_INI = os.path.join(PROJECT_DIR, "platformio.ini")


def _read_platformio():
    with open(PLATFORMIO_INI, "r") as f:
        return f.read()


def _zero_env_section(src):
    """Return the text of the [env:esp32s3_zero] section."""
    m = re.search(
        r"\[env:esp32s3_zero\](.*?)(?=\n\[env:|\Z)",
        src, re.DOTALL,
    )
    assert m, "[env:esp32s3_zero] section not found in platformio.ini"
    return m.group(0)


def test_platformio_zero_env_exists():
    """[env:esp32s3_zero] section exists in platformio.ini."""
    src = _read_platformio()
    assert "[env:esp32s3_zero]" in src, \
        "[env:esp32s3_zero] not found in platformio.ini"


def test_platformio_zero_defines_esptty_board_zero():
    """esp32s3_zero env has -DESPTTY_BOARD_ZERO in build_flags."""
    src = _read_platformio()
    section = _zero_env_section(src)
    assert "-DESPTTY_BOARD_ZERO" in section, (
        "-DESPTTY_BOARD_ZERO not found in [env:esp32s3_zero] build_flags. "
        "Firmware uses this macro to #ifdef Zero-specific behaviour."
    )


def test_platformio_zero_debug_env_defines_esptty_board_zero():
    """esp32s3_zero_debug env also has -DESPTTY_BOARD_ZERO in build_flags."""
    src = _read_platformio()
    m = re.search(
        r"\[env:esp32s3_zero_debug\](.*?)(?=\n\[env:|\Z)",
        src, re.DOTALL,
    )
    assert m, "[env:esp32s3_zero_debug] not found in platformio.ini"
    section = m.group(0)
    assert "-DESPTTY_BOARD_ZERO" in section, (
        "-DESPTTY_BOARD_ZERO missing from [env:esp32s3_zero_debug] build_flags."
    )


def test_platformio_zero_uses_zero_defaults_overlay():
    """esp32s3_zero cmake_extra_args includes sdkconfig.zero.defaults in the chain."""
    src = _read_platformio()
    section = _zero_env_section(src)
    assert "sdkconfig.zero.defaults" in section, (
        "sdkconfig.zero.defaults not referenced in [env:esp32s3_zero] "
        "cmake_extra_args SDKCONFIG_DEFAULTS. The overlay won't be applied."
    )


def test_platformio_zero_partitions_zero_csv():
    """esp32s3_zero env sets board_build.partitions to partitions_zero.csv."""
    src = _read_platformio()
    section = _zero_env_section(src)
    assert "partitions_zero.csv" in section, (
        "partitions_zero.csv not referenced in [env:esp32s3_zero]. "
        "The Zero has a different flash layout and needs its own partition table."
    )


def test_platformio_non_zero_env_lacks_esptty_board_zero():
    """Main [env:esp32s3] (DevKit) env does NOT define ESPTTY_BOARD_ZERO."""
    src = _read_platformio()
    m = re.search(
        r"\[env:esp32s3\](.*?)(?=\n\[env:|\Z)",
        src, re.DOTALL,
    )
    assert m, "[env:esp32s3] section not found in platformio.ini"
    section = m.group(0)
    assert "ESPTTY_BOARD_ZERO" not in section, (
        "ESPTTY_BOARD_ZERO found in [env:esp32s3] (DevKit) build_flags. "
        "This flag must only be set for Zero environments."
    )
