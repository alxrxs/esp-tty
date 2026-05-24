#!/usr/bin/env python3
"""
test/scripts/test_wifi_zero_runtime.py
-- Structural assertions on main/wifi.c for Zero-specific code paths.

Verifies that the Zero-stability workarounds added to wifi.c are structurally
present: country-code call in both init paths, PS disable after start,
WIFI_MAX_TX_POWER wrapped in #ifdef, reason-8 teardown branch.

Also scans for ESP_LOG* calls inside xSemaphoreTake blocks (the ESP-IDF
#13794 deadlock pattern -- logging while holding a FreeRTOS mutex can cause
nested lock acquisition and a cpu_compare_and_set spin that the WDT kills).
wifi.c should have ZERO such occurrences.

These are compile-time structural guards; they run instantly on the host
without hardware or a full ESP-IDF build.
"""

import os
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
WIFI_C      = os.path.join(PROJECT_DIR, "main", "wifi.c")


def _read_wifi_c():
    with open(WIFI_C, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Country-code call in wifi_init_sta (PSK / plain enterprise path)
# ---------------------------------------------------------------------------

def test_country_code_set_in_wifi_init_sta():
    """esp_wifi_set_country_code is called in wifi_init_sta after esp_wifi_init."""
    src = _read_wifi_c()

    # Locate wifi_init_sta function body (it is the only non-static entry point
    # for the PSK/enterprise path -- find it by its declaration).
    m = re.search(
        r"esp_err_t\s+wifi_init_sta\b(.*?)(?=\n(?:static\s+)?esp_err_t\s+\w|\Z)",
        src, re.DOTALL,
    )
    assert m, "wifi_init_sta() not found in main/wifi.c"
    body = m.group(0)

    # The country-code call must be present (inside the #ifdef guard).
    assert "esp_wifi_set_country_code" in body, (
        "esp_wifi_set_country_code not called in wifi_init_sta(). "
        "This call must appear after esp_wifi_init() to fully initialise "
        "the RF state machine for channels 12-13."
    )
    assert "esp_wifi_init" in body, \
        "esp_wifi_init not found in wifi_init_sta() -- unexpected refactor?"
    # The country-code call must come after esp_wifi_init in the text.
    idx_init = body.index("esp_wifi_init")
    idx_cc   = body.index("esp_wifi_set_country_code")
    assert idx_cc > idx_init, (
        "esp_wifi_set_country_code appears before esp_wifi_init in wifi_init_sta(). "
        "It must be called AFTER init to have effect."
    )


# ---------------------------------------------------------------------------
# Country-code call in wifi_smart_init_common (Mode B+ / Mode C shared preamble)
# ---------------------------------------------------------------------------

def test_country_code_set_in_wifi_smart_init_common():
    """esp_wifi_set_country_code is called in wifi_smart_init_common after esp_wifi_init."""
    src = _read_wifi_c()

    m = re.search(
        r"(?:static\s+)?esp_err_t\s+wifi_smart_init_common\b(.*?)(?=\n(?:static\s+)?esp_err_t\s+\w|\Z)",
        src, re.DOTALL,
    )
    assert m, (
        "wifi_smart_init_common() not found in main/wifi.c. "
        "This is the shared preamble for Mode B+ (wifi_init_enterprise_bootstrap) "
        "and Mode C (wifi_init_smart)."
    )
    body = m.group(0)

    assert "esp_wifi_set_country_code" in body, (
        "esp_wifi_set_country_code not called in wifi_smart_init_common(). "
        "The call must live in the shared preamble so both Mode B+ and Mode C "
        "benefit -- placing it only in wifi_init_sta would miss Mode B+/C paths."
    )
    assert "esp_wifi_init" in body, \
        "esp_wifi_init not found in wifi_smart_init_common() -- unexpected refactor?"
    idx_init = body.index("esp_wifi_init")
    idx_cc   = body.index("esp_wifi_set_country_code")
    assert idx_cc > idx_init, (
        "esp_wifi_set_country_code appears before esp_wifi_init in "
        "wifi_smart_init_common(). It must be called AFTER init."
    )


def test_country_code_called_in_both_init_paths():
    """esp_wifi_set_country_code appears in at least two distinct init contexts."""
    src = _read_wifi_c()
    # Count occurrences of the actual call (not the #ifdef guard macro name)
    calls = re.findall(r"esp_wifi_set_country_code\s*\(", src)
    assert len(calls) >= 2, (
        f"esp_wifi_set_country_code found only {len(calls)} time(s) in wifi.c; "
        "expected at least 2 (once in wifi_init_sta and once in wifi_smart_init_common). "
        "A missing call means one of the init paths skips the country-code setup."
    )


# ---------------------------------------------------------------------------
# WIFI_MAX_TX_POWER wrapped in #ifdef
# ---------------------------------------------------------------------------

def test_wifi_max_tx_power_inside_ifdef():
    """WIFI_MAX_TX_POWER usage is wrapped in #ifdef WIFI_MAX_TX_POWER guard."""
    src = _read_wifi_c()
    assert "WIFI_MAX_TX_POWER" in src, \
        "WIFI_MAX_TX_POWER not referenced in wifi.c at all"

    # Find the #ifdef WIFI_MAX_TX_POWER guard
    m_guard = re.search(r"#ifdef\s+WIFI_MAX_TX_POWER", src)
    assert m_guard, (
        "#ifdef WIFI_MAX_TX_POWER not found in wifi.c. "
        "The TX power cap must be gated so DevKit builds without the macro "
        "still compile (WIFI_MAX_TX_POWER is only defined in Zero configs)."
    )

    # The esp_wifi_set_max_tx_power call must exist and be after the guard
    m_call = re.search(r"esp_wifi_set_max_tx_power\s*\(", src)
    assert m_call, "esp_wifi_set_max_tx_power call not found in wifi.c"

    assert m_call.start() > m_guard.start(), (
        "esp_wifi_set_max_tx_power call appears before the #ifdef WIFI_MAX_TX_POWER "
        "guard -- the call may be compiled unconditionally."
    )


def test_wifi_max_tx_power_followed_by_endif():
    """The #ifdef WIFI_MAX_TX_POWER block is closed by a matching #endif."""
    src = _read_wifi_c()
    m_guard = re.search(r"#ifdef\s+WIFI_MAX_TX_POWER", src)
    assert m_guard, "#ifdef WIFI_MAX_TX_POWER not found"

    after_guard = src[m_guard.start():]
    assert "#endif" in after_guard, (
        "#endif not found after #ifdef WIFI_MAX_TX_POWER -- unclosed guard?"
    )


# ---------------------------------------------------------------------------
# esp_wifi_set_ps(WIFI_PS_NONE) in wifi_mode_psk
# ---------------------------------------------------------------------------

def test_wifi_ps_none_called_after_esp_wifi_start_in_psk():
    """esp_wifi_set_ps(WIFI_PS_NONE) is called after esp_wifi_start in wifi_mode_psk."""
    src = _read_wifi_c()

    # Extract wifi_mode_psk body
    m = re.search(
        r"static\s+esp_err_t\s+wifi_mode_psk\b(.*?)(?=\nstatic\s+(?:bool|esp_err_t)\s+\w|\Z)",
        src, re.DOTALL,
    )
    assert m, "wifi_mode_psk() not found in main/wifi.c"
    body = m.group(0)

    assert "esp_wifi_set_ps" in body, (
        "esp_wifi_set_ps not called in wifi_mode_psk(). "
        "On the Zero (FH4R2 v0.2) the default WIFI_PS_MIN_MODEM can trigger "
        "an IntegerDivideByZero in pm_get_tbtt_count inside libpp.a. "
        "WIFI_PS_NONE must be set after esp_wifi_start."
    )
    assert "WIFI_PS_NONE" in body, \
        "WIFI_PS_NONE not referenced in wifi_mode_psk()"

    # PS disable must come after esp_wifi_start
    assert "esp_wifi_start" in body, \
        "esp_wifi_start not found in wifi_mode_psk() -- unexpected refactor?"
    idx_start = body.index("esp_wifi_start")
    idx_ps    = body.index("esp_wifi_set_ps")
    assert idx_ps > idx_start, (
        "esp_wifi_set_ps appears before esp_wifi_start in wifi_mode_psk(). "
        "The PS mode must be changed AFTER the driver is started."
    )


def test_wifi_ps_none_present_in_file():
    """WIFI_PS_NONE is referenced in wifi.c at least once."""
    src = _read_wifi_c()
    assert "WIFI_PS_NONE" in src, \
        "WIFI_PS_NONE not found anywhere in wifi.c"


# ---------------------------------------------------------------------------
# Reason-8 (ASSOC_LEAVE) planned-teardown branch in STA_DISCONNECTED handler
# ---------------------------------------------------------------------------

def test_assoc_leave_reason_handled_as_planned_teardown():
    """STA_DISCONNECTED handler has a branch for WIFI_REASON_ASSOC_LEAVE (reason 8)."""
    src = _read_wifi_c()
    assert "WIFI_REASON_ASSOC_LEAVE" in src, (
        "WIFI_REASON_ASSOC_LEAVE not referenced in wifi.c. "
        "The disconnect handler must treat reason 8 as a planned teardown "
        "(no auto-reconnect, INFO log not WARN) to avoid racing the next "
        "wifi_mode_* call during PSK->enterprise transition."
    )


def test_assoc_leave_branch_uses_info_log():
    """The ASSOC_LEAVE branch logs at INFO level (not WARN/ERROR)."""
    src = _read_wifi_c()
    # Find the ASSOC_LEAVE branch -- should contain an ESP_LOGI call with
    # "planned teardown" text.
    assert "planned teardown" in src, (
        "'planned teardown' comment/log not found in wifi.c. "
        "The WIFI_REASON_ASSOC_LEAVE handler should log at INFO level with a "
        "'planned teardown' message so it is distinguishable from unexpected disconnects."
    )
    # Ensure it uses LOGI, not LOGW/LOGE for this message
    m = re.search(r"ESP_LOG([IWED])\s*\([^)]*planned teardown", src)
    assert m, "ESP_LOG* call containing 'planned teardown' not found in wifi.c"
    level = m.group(1)
    assert level == "I", (
        f"'planned teardown' is logged at level {level!r} -- expected 'I' (INFO). "
        "A WARN or ERROR level for an intentional teardown pollutes the boot log."
    )


def test_assoc_leave_skips_reconnect():
    """The ASSOC_LEAVE branch skips the auto-reconnect block (goto or early return)."""
    src = _read_wifi_c()
    # The canonical pattern is `goto disc_done` after the ASSOC_LEAVE check.
    # Accept either goto or return as a valid skip mechanism.
    m_block = re.search(
        r"WIFI_REASON_ASSOC_LEAVE(.*?)(?=WIFI_MAX_RETRY|s_retry_num)",
        src, re.DOTALL,
    )
    assert m_block, (
        "Could not find the code between WIFI_REASON_ASSOC_LEAVE and the retry "
        "block -- please verify the handler structure."
    )
    between = m_block.group(1)
    has_skip = "goto" in between or "return" in between
    assert has_skip, (
        "No 'goto' or 'return' found between the WIFI_REASON_ASSOC_LEAVE check "
        "and the reconnect block. The handler must skip auto-reconnect for "
        "planned teardowns to avoid racing the next wifi_mode_* call."
    )


# ---------------------------------------------------------------------------
# No ESP_LOG* calls inside xSemaphoreTake / critical-section blocks
# (ESP-IDF #13794 deadlock pattern)
# ---------------------------------------------------------------------------

def test_no_esplog_inside_semaphore_take_blocks():
    """No ESP_LOG* calls appear inside xSemaphoreTake...xSemaphoreGive blocks.

    Calling ESP_LOG* while holding a FreeRTOS semaphore can cause the USB-
    Serial-JTAG (USJ) console driver to call xRingbufferSend, which takes its
    own lock.  The nested acquisition causes esp_cpu_compare_and_set to spin
    forever and the interrupt WDT fires (ESP-IDF #13794).

    NOTE: If this test ever FAILS it should be treated as a bug report, not
    silenced.  Do not move logging calls inside a semaphore-held region.
    """
    src = _read_wifi_c()

    # wifi.c currently uses no xSemaphoreTake at all -- verify that first.
    # If a future refactor adds semaphores, the nested-log check below catches
    # any ESP_LOG* accidentally placed inside the guarded region.
    semaphore_blocks = list(re.finditer(r"xSemaphoreTake\s*\(", src))
    if not semaphore_blocks:
        # No semaphores in file -- trivially safe.
        return

    # For each xSemaphoreTake, find the matching xSemaphoreGive and scan for
    # ESP_LOG* between them.
    violations = []
    for take_m in semaphore_blocks:
        after_take = src[take_m.end():]
        give_m = re.search(r"xSemaphoreGive\s*\(", after_take)
        if not give_m:
            continue
        between = after_take[:give_m.start()]
        logs = re.findall(r"ESP_LOG[IWED]\s*\(", between)
        if logs:
            # Find approximate line number
            line_no = src[:take_m.start()].count("\n") + 1
            violations.append(
                f"Line ~{line_no}: {len(logs)} ESP_LOG call(s) inside xSemaphoreTake block"
            )

    assert not violations, (
        "ESP_LOG* calls found inside xSemaphoreTake blocks in wifi.c -- "
        "this is the ESP-IDF #13794 deadlock pattern (USJ nested lock):\n"
        + "\n".join(violations)
    )


def test_no_esplog_inside_critical_sections():
    """No ESP_LOG* calls appear inside portENTER_CRITICAL / taskENTER_CRITICAL blocks."""
    src = _read_wifi_c()

    critical_entries = list(re.finditer(
        r"(?:portENTER_CRITICAL|taskENTER_CRITICAL)\s*\(", src
    ))
    if not critical_entries:
        # No critical sections -- trivially safe.
        return

    violations = []
    for entry_m in critical_entries:
        after_entry = src[entry_m.end():]
        exit_m = re.search(
            r"(?:portEXIT_CRITICAL|taskEXIT_CRITICAL)\s*\(", after_entry
        )
        if not exit_m:
            continue
        between = after_entry[:exit_m.start()]
        logs = re.findall(r"ESP_LOG[IWED]\s*\(", between)
        if logs:
            line_no = src[:entry_m.start()].count("\n") + 1
            violations.append(
                f"Line ~{line_no}: {len(logs)} ESP_LOG call(s) inside critical section"
            )

    assert not violations, (
        "ESP_LOG* calls found inside critical sections in wifi.c -- "
        "this is the ESP-IDF #13794 deadlock pattern:\n"
        + "\n".join(violations)
    )


# ---------------------------------------------------------------------------
# WIFI_COUNTRY_CODE guard is an #ifdef (optional macro, not unconditional)
# ---------------------------------------------------------------------------

def test_country_code_wrapped_in_ifdef():
    """WIFI_COUNTRY_CODE usage is wrapped in #ifdef so builds without it compile."""
    src = _read_wifi_c()
    assert "#ifdef WIFI_COUNTRY_CODE" in src, (
        "#ifdef WIFI_COUNTRY_CODE not found in wifi.c. "
        "The country-code path must be gated so DevKit builds without the macro "
        "still compile."
    )


def test_wifi_country_code_ifdef_count_matches_call_count():
    """Number of #ifdef WIFI_COUNTRY_CODE guards matches the number of actual call sites.

    Each #ifdef block contains exactly one esp_wifi_set_country_code() call
    (the LOGW fallback line only embeds the function name as a format string,
    not a real call).  Count only assignment-context calls (lines that begin
    with 'esp_err_t cc_err = esp_wifi_set_country_code(') to avoid
    false-positives from log format strings.
    """
    src = _read_wifi_c()
    guards = re.findall(r"#ifdef\s+WIFI_COUNTRY_CODE", src)
    # Real calls: assigned to a variable (not inside a string literal)
    calls  = re.findall(r"\besp_wifi_set_country_code\s*\([^\"']*,\s*true\s*\)", src)
    assert len(guards) == len(calls), (
        f"Found {len(guards)} #ifdef WIFI_COUNTRY_CODE guard(s) but "
        f"{len(calls)} esp_wifi_set_country_code(... , true) call(s). "
        "Each call site should have its own guard."
    )
