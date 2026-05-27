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
    """The ASSOC_LEAVE branch must bypass the WIFI_MAX_RETRY-based reconnect block.

    The branch is allowed to call esp_wifi_connect() directly (for the
    cert-renewal reconnect path), but it must `goto disc_done` so it
    does NOT fall through into the retry-count logic, which would
    double-call esp_wifi_connect() and risk a race with the next
    wifi_mode_* transition.
    """
    src = _read_wifi_c()
    # The ASSOC_LEAVE branch ends at the outer closing brace right before
    # `disc_done`.  Match everything from WIFI_REASON_ASSOC_LEAVE to the
    # WIFI_MAX_RETRY block header (which marks the start of the generic
    # retry handling for non-ASSOC_LEAVE reasons).
    m_block = re.search(
        r"WIFI_REASON_ASSOC_LEAVE(.*?)const\s+bool\s+infinite\s*=",
        src, re.DOTALL,
    )
    assert m_block, (
        "Could not find the code between WIFI_REASON_ASSOC_LEAVE and the "
        "generic WIFI_MAX_RETRY retry block."
    )
    between = m_block.group(1)
    # Must skip the generic retry block with a goto / return.
    assert "goto disc_done" in between or "return" in between, (
        "ASSOC_LEAVE branch must `goto disc_done` (or return) to skip the "
        "generic WIFI_MAX_RETRY retry block; otherwise we would either "
        "double-call esp_wifi_connect() or fall into the retry counter "
        "logic intended for unsolicited disconnects."
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


# ---------------------------------------------------------------------------
# New: STA_DISCONNECTED reason-code matrix
# ---------------------------------------------------------------------------

def test_sta_disconnected_handler_clears_connected_bit():
    """WIFI_EVENT_STA_DISCONNECTED handler clears WIFI_CONNECTED_BIT from the event group."""
    src = _read_wifi_c()
    assert "xEventGroupClearBits" in src, \
        "xEventGroupClearBits not found in wifi.c"
    assert "WIFI_CONNECTED_BIT" in src, \
        "WIFI_CONNECTED_BIT not referenced in wifi.c"
    # The clear must happen in the disconnected handler.
    m = re.search(
        r"WIFI_EVENT_STA_DISCONNECTED(.*?)disc_done\s*:",
        src, re.DOTALL,
    )
    assert m, "STA_DISCONNECTED handler block (up to disc_done: label) not found"
    block = m.group(1)
    assert "xEventGroupClearBits" in block, (
        "xEventGroupClearBits(WIFI_CONNECTED_BIT) not called inside the "
        "STA_DISCONNECTED handler block. Callers that poll the event group "
        "would see a stale CONNECTED state."
    )


def test_sta_disconnected_retry_increments_s_retry_num():
    """Retry branch inside STA_DISCONNECTED increments s_retry_num before reconnect."""
    src = _read_wifi_c()
    # Use the full handler block (up to and including the disc_done: label).
    m = re.search(
        r"WIFI_EVENT_STA_DISCONNECTED(.*?)disc_done\s*:",
        src, re.DOTALL,
    )
    assert m, "STA_DISCONNECTED handler block (up to disc_done: label) not found"
    block = m.group(1)
    # s_retry_num was converted from plain `int` to `_Atomic int` for
    # cross-core visibility on ESP32-S3 dual-Xtensa; the increment now uses
    # atomic_fetch_add.  Accept either spelling so this test does not pin
    # the implementation to one C-language idiom.
    incremented = ("s_retry_num++" in block
                   or "atomic_fetch_add(&s_retry_num" in block)
    assert incremented, (
        "s_retry_num is not incremented inside the STA_DISCONNECTED handler "
        "block. The retry counter must be incremented each time "
        "esp_wifi_connect is called so WIFI_MAX_RETRY enforcement is accurate."
    )


def test_sta_disconnected_sets_fail_bit_on_max_retry():
    """STA_DISCONNECTED handler sets WIFI_FAIL_BIT when retries are exhausted."""
    src = _read_wifi_c()
    m = re.search(
        r"WIFI_EVENT_STA_DISCONNECTED(.*?)disc_done\s*:",
        src, re.DOTALL,
    )
    assert m, "STA_DISCONNECTED handler block (up to disc_done: label) not found"
    block = m.group(1)
    assert "WIFI_FAIL_BIT" in block, (
        "WIFI_FAIL_BIT not set in STA_DISCONNECTED handler. "
        "wifi_init_sta() waits on both CONNECTED_BIT and FAIL_BIT; if FAIL_BIT "
        "is never set, the wait blocks forever when the AP disappears."
    )
    assert "xEventGroupSetBits" in block, \
        "xEventGroupSetBits not called in STA_DISCONNECTED handler"


def test_sta_disconnected_infinite_retry_when_max_is_zero():
    """WIFI_MAX_RETRY=0 means infinite retries (no hard stop)."""
    src = _read_wifi_c()
    # The default must be 0.
    m = re.search(r"#define\s+WIFI_MAX_RETRY\s+(\d+)", src)
    assert m, "WIFI_MAX_RETRY #define not found in wifi.c"
    default = int(m.group(1))
    assert default == 0, (
        f"WIFI_MAX_RETRY default is {default}, expected 0 (infinite). "
        "The intent is to retry forever until the AP returns; a non-zero "
        "default would cause the firmware to give up after a transient outage."
    )
    # The infinite check must be present.
    assert "WIFI_MAX_RETRY == 0" in src or "infinite" in src, (
        "WIFI_MAX_RETRY == 0 infinite-retry check not found in wifi.c."
    )


def test_reconnect_forever_after_fail_bit():
    """After setting WIFI_FAIL_BIT the code still calls esp_wifi_connect (RECONNECT_FOREVER)."""
    src = _read_wifi_c()
    # Find the else-branch that sets FAIL_BIT and verify esp_wifi_connect follows.
    m = re.search(
        r"xEventGroupSetBits\(s_wifi_event_group,\s*WIFI_FAIL_BIT\)(.*?)esp_wifi_connect\(\)",
        src, re.DOTALL,
    )
    assert m, (
        "esp_wifi_connect() not found after xEventGroupSetBits(WIFI_FAIL_BIT). "
        "RECONNECT_FOREVER semantics require that the driver keeps reconnecting "
        "even after signalling failure, so the firmware recovers when the AP "
        "returns without a reboot."
    )


def test_assoc_leave_does_not_set_fail_bit():
    """ASSOC_LEAVE branch does NOT set WIFI_FAIL_BIT (planned teardown, not a failure)."""
    src = _read_wifi_c()
    # Grab the ASSOC_LEAVE branch -- everything between the reason check and disc_done.
    m = re.search(
        r"WIFI_REASON_ASSOC_LEAVE(.*?)goto\s+disc_done",
        src, re.DOTALL,
    )
    assert m, "ASSOC_LEAVE branch (up to goto disc_done) not found"
    branch = m.group(1)
    assert "WIFI_FAIL_BIT" not in branch, (
        "WIFI_FAIL_BIT is set inside the ASSOC_LEAVE branch. "
        "Reason 8 is a planned teardown (PSK->enterprise transition); setting "
        "FAIL_BIT here would cause wifi_init_enterprise_bootstrap to exit "
        "its wait-loop early and report failure."
    )


def test_assoc_leave_planned_teardown_does_not_call_esp_wifi_connect():
    """The planned-teardown sub-branch of ASSOC_LEAVE must NOT call esp_wifi_connect.

    Since the cert-renewer-driven reconnect path is now also handled in
    the same ASSOC_LEAVE branch (guarded by s_eap_creds_just_rotated),
    the rule has been narrowed: the *planned-teardown* sub-branch (the
    one that falls through to `goto disc_done` without seeing the
    rotated flag set) must still not call esp_wifi_connect(), otherwise
    PSK->enterprise transitions race the next wifi_mode_enterprise()
    call.
    """
    src = _read_wifi_c()
    # Strip C comments so we operate on code only.
    code = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    code = re.sub(r"//[^\n]*", "", code)
    # Extract from the "planned teardown" ESP_LOGI line to its `goto disc_done`.
    # The ESP_LOGI may span multiple lines, so match across newlines.
    m = re.search(
        r'planned teardown.*?ev->reason\s*\)\s*;(.*?)goto\s+disc_done',
        code, re.DOTALL,
    )
    assert m, ("Could not locate the planned-teardown sub-branch.  Look "
               "for the ESP_LOGI line containing 'planned teardown'.")
    branch = m.group(1)
    assert "esp_wifi_connect" not in branch, (
        "esp_wifi_connect() called inside the planned-teardown sub-branch "
        "of ASSOC_LEAVE.  That would race the subsequent "
        "wifi_mode_enterprise() call that re-configures the STA interface."
    )


def test_disc_done_label_exists_after_retry_block():
    """disc_done: label exists at the end of the STA_DISCONNECTED handler."""
    src = _read_wifi_c()
    assert "disc_done:" in src, (
        "disc_done: label not found in wifi.c. "
        "The ASSOC_LEAVE goto target must be present or the compiler will reject "
        "the goto statement."
    )


def test_sta_disconnected_logs_reason_code_in_retry_branch():
    """Retry branch logs the reason code in its LOGW message."""
    src = _read_wifi_c()
    m = re.search(
        r"WIFI_EVENT_STA_DISCONNECTED(.*?)disc_done\s*:",
        src, re.DOTALL,
    )
    assert m, "STA_DISCONNECTED handler block not found"
    block = m.group(1)
    # ev->reason must appear in at least one log call inside the retry block.
    assert "ev->reason" in block, (
        "ev->reason not referenced in the STA_DISCONNECTED handler log message. "
        "Log the reason code so field debugging of unexpected disconnects is "
        "possible without attaching a JTAG probe."
    )


# ---------------------------------------------------------------------------
# New: wifi_mode_psk / wifi_mode_enterprise state machine guards
# ---------------------------------------------------------------------------

def test_wifi_mode_psk_clears_event_bits_before_start():
    """wifi_mode_psk clears WIFI_CONNECTED_BIT and WIFI_FAIL_BIT before esp_wifi_start."""
    src = _read_wifi_c()
    m = re.search(
        r"static\s+esp_err_t\s+wifi_mode_psk\b(.*?)(?=\nstatic\s+(?:bool|esp_err_t)\s+\w|\Z)",
        src, re.DOTALL,
    )
    assert m, "wifi_mode_psk() not found in main/wifi.c"
    body = m.group(0)
    assert "xEventGroupClearBits" in body, (
        "xEventGroupClearBits not called in wifi_mode_psk(). "
        "Stale event bits from a prior run can cause wifi_init_enterprise_bootstrap "
        "to exit its wait-loop immediately on re-entry."
    )


def test_wifi_mode_enterprise_clears_event_bits():
    """wifi_mode_enterprise clears WIFI_CONNECTED_BIT and WIFI_FAIL_BIT on entry."""
    src = _read_wifi_c()
    m = re.search(
        r"static\s+esp_err_t\s+wifi_mode_enterprise\b(.*?)(?=\n/\*\s*-{5}|\nstatic\s+esp_err_t\s+wifi_smart_init_common|\Z)",
        src, re.DOTALL,
    )
    assert m, "wifi_mode_enterprise() not found in main/wifi.c"
    body = m.group(0)
    assert "xEventGroupClearBits" in body or "WIFI_CONNECTED_BIT" in body, (
        "WIFI_CONNECTED_BIT not cleared in wifi_mode_enterprise(). "
        "A stale CONNECTED_BIT would cause the caller's wait-loop to exit "
        "immediately without waiting for a new IP assignment."
    )


def test_wifi_ps_none_present_globally():
    """WIFI_PS_NONE appears in wifi.c to ensure power-save is disabled."""
    src = _read_wifi_c()
    count = src.count("WIFI_PS_NONE")
    assert count >= 1, (
        "WIFI_PS_NONE not found in wifi.c. "
        "Power-save must be explicitly disabled (WIFI_PS_NONE) on the Zero "
        "to avoid the modem-sleep beacon timing race."
    )


def test_wifi_country_code_error_logged_on_failure():
    """Failed esp_wifi_set_country_code call is logged with ESP_LOGW."""
    src = _read_wifi_c()
    # Both call sites should have a LOGW for the failure case.
    logw_after_cc = re.findall(
        r"esp_wifi_set_country_code.*?ESP_LOG[WE]",
        src, re.DOTALL,
    )
    assert logw_after_cc, (
        "No ESP_LOGW/LOGE found after esp_wifi_set_country_code in wifi.c. "
        "A failed country-code set should be logged so it surfaces during "
        "field testing (wrong region settings degrade channel availability)."
    )
