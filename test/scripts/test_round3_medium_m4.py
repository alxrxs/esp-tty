"""
test_round3_medium_m4.py -- structural pytests for round-3 MEDIUM fixes (M4.A..M4.C)

M4.A: main.c must not use ESP_ERROR_CHECK on recoverable init paths (usb_cdc_init,
      ssh_server_start).  NVS-init and partition-lookup aborts are kept because
      they are genuinely non-recoverable at boot.

M4.B: sdkconfig.debug_console.defaults must enable -Og (CONFIG_COMPILER_OPTIMIZATION_DEBUG=y)
      and disable -O2 so GDB can step through debug builds without everything
      showing as <optimized out>.

M4.C: sdkconfig.defaults SPIRAM comment must accurately describe the IDF default
      (SPIRAM_USE_MALLOC=y, 16 KB threshold) and the Zero delta (256-byte threshold).
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# M4.A -- recoverable init paths must NOT use ESP_ERROR_CHECK
# ---------------------------------------------------------------------------

def test_m4a_usb_cdc_init_not_wrapped_in_esp_error_check():
    src = _read("main/main.c")
    # The usb_cdc_init call must NOT appear inside ESP_ERROR_CHECK(usb_cdc_init(
    assert "ESP_ERROR_CHECK(usb_cdc_init(" not in src, (
        "usb_cdc_init is a recoverable failure (TinyUSB OOM); must not be "
        "wrapped in ESP_ERROR_CHECK.  See M4.A."
    )
    # It MUST still be called (not removed).
    assert "usb_cdc_init(" in src, (
        "usb_cdc_init must still be called -- the fix is to relax the error "
        "handling, not to delete the call."
    )


def test_m4a_ssh_server_start_not_wrapped_in_esp_error_check():
    src = _read("main/main.c")
    assert "ESP_ERROR_CHECK(ssh_server_start(" not in src, (
        "ssh_server_start is a recoverable failure; must not be wrapped in "
        "ESP_ERROR_CHECK.  SSH failure should log + continue, not abort.  See M4.A."
    )
    assert "ssh_server_start(" in src, (
        "ssh_server_start must still be called."
    )


def test_m4a_usb_cdc_init_error_is_logged():
    src = _read("main/main.c")
    # The explicit error handler must log via ESP_LOGE.
    assert "usb_cdc_init failed" in src or "USB CDC bridge unavailable" in src, (
        "When usb_cdc_init fails, main.c must log the error with ESP_LOGE.  See M4.A."
    )


def test_m4a_ssh_server_start_error_is_logged():
    src = _read("main/main.c")
    assert "ssh_server_start failed" in src or "SSH unavailable" in src, (
        "When ssh_server_start fails, main.c must log the error with ESP_LOGE.  See M4.A."
    )


def test_m4a_esp_error_check_count_in_main_c():
    """Baseline check: ESP_ERROR_CHECK in main.c must only appear on genuinely
    non-recoverable paths (NVS key generation, NVS flash init, partition erase).
    The set of allowed sites is small; if it grows, this test fails and the
    reviewer must justify the new site.

    Allowed sites:
      - ESP_ERROR_CHECK(nvs_flash_generate_keys(...))  -- NVS key gen, no recovery path
      - ESP_ERROR_CHECK(esp_partition_erase_range(...)) -- pre-reinit erase, no recovery path
      - ESP_ERROR_CHECK(err)                            -- bare check after nvs_flash_secure_init_partition
                                                           or nvs_flash_read_security_cfg; both are NVS
                                                           init paths where failure means the encrypted
                                                           store is inaccessible (device must be re-flashed)
    """
    src = _read("main/main.c")
    sites = [line.strip() for line in src.splitlines()
             if "ESP_ERROR_CHECK(" in line and not line.strip().startswith("//")
             and not line.strip().startswith("*")]
    # Allowed sites (NVS init path only):
    allowed_patterns = [
        "nvs_flash_generate_keys",
        "nvs_flash_secure_init_partition",
        "esp_partition_erase_range",
        # Bare ESP_ERROR_CHECK(err) appears twice in the NVS-init block:
        # once for the nvs_flash_read_security_cfg unknown-error branch,
        # once for the final nvs_flash_secure_init_partition result.
        "ESP_ERROR_CHECK(err)",
    ]
    for site in sites:
        assert any(pat in site for pat in allowed_patterns), (
            f"Unexpected ESP_ERROR_CHECK in main.c: {site!r}\n"
            "Only NVS-init paths (nvs_flash_generate_keys, "
            "nvs_flash_secure_init_partition, esp_partition_erase_range, "
            "or bare ESP_ERROR_CHECK(err) in the NVS block) "
            "may use ESP_ERROR_CHECK.  See M4.A."
        )


# ---------------------------------------------------------------------------
# M4.B -- debug builds use -Og, not -O2
# ---------------------------------------------------------------------------

def test_m4b_debug_console_defaults_sets_optimization_debug():
    src = _read("sdkconfig.debug_console.defaults")
    assert "CONFIG_COMPILER_OPTIMIZATION_DEBUG=y" in src, (
        "sdkconfig.debug_console.defaults must set CONFIG_COMPILER_OPTIMIZATION_DEBUG=y "
        "(-Og) so GDB can step through debug builds.  See M4.B."
    )


def test_m4b_debug_console_defaults_disables_optimization_perf():
    src = _read("sdkconfig.debug_console.defaults")
    # Must explicitly unset -O2 so the base sdkconfig.defaults setting is overridden.
    assert "CONFIG_COMPILER_OPTIMIZATION_PERF=n" in src, (
        "sdkconfig.debug_console.defaults must set CONFIG_COMPILER_OPTIMIZATION_PERF=n "
        "to override the base -O2 setting from sdkconfig.defaults.  See M4.B."
    )


def test_m4b_debug_console_defaults_has_rationale_comment():
    src = _read("sdkconfig.debug_console.defaults")
    # Ensure there's a comment explaining the developer tradeoff.
    assert "GDB" in src, (
        "sdkconfig.debug_console.defaults must include a comment explaining "
        "the -Og tradeoff (GDB stepping vs performance).  See M4.B."
    )


# ---------------------------------------------------------------------------
# M4.C -- sdkconfig.defaults SPIRAM comment reflects IDF default behaviour
# ---------------------------------------------------------------------------

def test_m4c_spiram_comment_mentions_idf_default():
    src = _read("sdkconfig.defaults")
    # The comment must acknowledge the IDF default (enabled, 16 KB threshold).
    assert "16384" in src or "16 KB" in src, (
        "sdkconfig.defaults must document the IDF default SPIRAM_USE_MALLOC "
        "threshold (16384 bytes / 16 KB).  See M4.C."
    )


def test_m4c_spiram_comment_mentions_zero_override():
    src = _read("sdkconfig.defaults")
    # Must cross-reference the Zero overlay's 256-byte threshold.
    assert "256" in src, (
        "sdkconfig.defaults must document that sdkconfig.zero.defaults "
        "overrides the threshold to 256 bytes.  See M4.C."
    )


def test_m4c_spiram_comment_no_false_do_not_set_claim():
    src = _read("sdkconfig.defaults")
    # The old misleading "Do NOT set CONFIG_SPIRAM_USE_MALLOC" comment must be gone.
    assert "Do NOT set CONFIG_SPIRAM_USE_MALLOC" not in src, (
        "The old 'Do NOT set CONFIG_SPIRAM_USE_MALLOC' comment was factually "
        "wrong -- the IDF default IS to enable it.  The comment must be "
        "replaced with an accurate description.  See M4.C."
    )
