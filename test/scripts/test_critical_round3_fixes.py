"""
test_critical_round3_fixes.py -- regression tests for round-3 CRITICAL fixes.

C1.A: cross-task scalars use _Atomic, not volatile, so ESP32-S3 dual-core
      memory ordering is well-defined.

C1.B: wifi_smart_init_common is idempotent -- on a second call it writes the
      cached handler instances into the out-parameters instead of returning
      INVALID_STATE without touching them, so the callers' subsequent
      esp_event_handler_instance_unregister sees valid handles.  Also: the
      event-group reset must NOT precede the double-init guard, because the
      reset is destructive (delete + recreate) and would invalidate handles
      previously stored by tasks that hold references to the original group.

C1.C: USB CDC boot-trigger has a single-shot atomic guard, captures the
      xTaskCreate return, and the deferred task runs at low priority so it
      cannot preempt the TinyUSB callback unwind.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(p: str) -> str:
    return (REPO / p).read_text()


# ----------------------------- C1.A -----------------------------------------

def test_c1a_s_pump_stop_is_atomic_bool():
    src = _read("main/ssh_server.c")
    assert re.search(r"_Atomic\s+bool\s+s_pump_stop", src), (
        "s_pump_stop must be declared _Atomic bool for cross-core visibility."
    )
    # No bare reads / writes outside atomic_load/store.  Excludes the
    # declaration line itself (which uses `=` for an initialiser, not an
    # assignment that must be atomic).
    body_only = re.sub(
        r"static\s+_Atomic\s+bool\s+s_pump_stop[^;]*;", "", src,
    )
    bare = re.findall(r"\bs_pump_stop\s*=\s*(?:true|false)\s*;", body_only)
    assert not bare, (
        f"All writes to s_pump_stop must go through atomic_store; "
        f"found bare assignments: {bare}"
    )


def test_c1a_s_ssh_listening_is_atomic_bool():
    src = _read("main/ssh_server.c")
    assert re.search(r"_Atomic\s+bool\s+s_ssh_listening", src)
    assert "atomic_load(&s_ssh_listening)" in src
    assert "atomic_store(&s_ssh_listening, true)" in src


def test_c1a_s_retry_num_is_atomic_int():
    src = _read("main/wifi.c")
    assert re.search(r"_Atomic\s+int\s+s_retry_num", src)
    assert "atomic_fetch_add(&s_retry_num" in src
    assert "atomic_store(&s_retry_num, 0)" in src


def test_c1a_udp_log_running_installed_atomic():
    src = _read("lib/udp_log/udp_log.c")
    assert re.search(r"_Atomic\s+bool\s+s_running", src)
    assert re.search(r"_Atomic\s+bool\s+s_installed", src)
    assert "atomic_load(&s_running)" in src
    assert "atomic_exchange(&s_installed" in src


def test_c1a_bridge_pump_signature_uses_atomic():
    h = _read("lib/bridge/bridge.h")
    assert "_Atomic bool   *stop" in h or "_Atomic bool *stop" in h, (
        "bridge_pump's stop parameter must be _Atomic bool * (not volatile)."
    )
    c = _read("lib/bridge/bridge.c")
    assert "atomic_load(stop)" in c, (
        "bridge_pump must dereference stop via atomic_load."
    )


# ----------------------------- C1.B -----------------------------------------

def test_c1b_smart_init_common_returns_ok_on_already_inited():
    """The idempotent path must write cached handles and return ESP_OK."""
    src = _read("main/wifi.c")
    # Find the wifi_smart_init_common body.
    m = re.search(
        r"static\s+esp_err_t\s+wifi_smart_init_common\b[^{]*\{(.*?)^\}",
        src, re.DOTALL | re.MULTILINE,
    )
    assert m, "wifi_smart_init_common body not found"
    body = m.group(1)

    # The already-inited path must populate the out-parameters from cache
    # before returning -- otherwise callers use uninitialised handles.
    assert "*out_inst_wifi = s_cached_inst_wifi" in body
    assert "*out_inst_ip   = s_cached_inst_ip" in body or \
           "*out_inst_ip = s_cached_inst_ip" in body
    # And it must return ESP_OK on that branch, not ESP_ERR_INVALID_STATE.
    already_block = re.search(
        r"if\s*\(already_inited\)\s*\{(.*?)\}", body, re.DOTALL,
    )
    assert already_block, "already_inited block not found"
    ab = already_block.group(1)
    assert "return ESP_OK" in ab, (
        "already-inited branch must return ESP_OK so callers proceed with "
        "the cached handles."
    )


def test_c1b_smart_init_guard_precedes_event_group_reset():
    """The destructive wifi_event_group_reset() must not run on re-entry."""
    src = _read("main/wifi.c")
    m = re.search(
        r"static\s+esp_err_t\s+wifi_smart_init_common\b[^{]*\{(.*?)^\}",
        src, re.DOTALL | re.MULTILINE,
    )
    body = m.group(1)
    # Strip comments so we compare ordering of actual statements, not docs.
    stripped = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    stripped = re.sub(r"//[^\n]*", "", stripped)
    guard_idx = stripped.find("atomic_exchange(&s_wifi_inited")
    reset_idx = stripped.find("wifi_event_group_reset()")
    assert guard_idx > 0 and reset_idx > 0
    assert guard_idx < reset_idx, (
        "Double-init guard must precede wifi_event_group_reset(); otherwise "
        "the destructive delete+recreate runs even when we then bail out."
    )


def test_c1b_callers_capture_smart_init_return():
    src = _read("main/wifi.c")
    # Both call sites should look like: <type> init_err = wifi_smart_init_common(...)
    occurrences = re.findall(
        r"wifi_smart_init_common\s*\(", src,
    )
    # 1 in definition + 2 in call sites
    assert len(occurrences) >= 3
    assert "init_err = wifi_smart_init_common(" in src, (
        "Callers must capture the return of wifi_smart_init_common."
    )
    # Both callers should emit an ESP_LOGE on failure.
    assert src.count("wifi_smart_init_common failed") >= 2


# ----------------------------- C1.C -----------------------------------------

def test_c1c_boot_trigger_single_shot_guard():
    src = _read("main/usb_cdc.c")
    assert re.search(r"_Atomic\s+bool\s+s_boot_triggered", src), (
        "Single-shot guard s_boot_triggered must be _Atomic bool."
    )
    # Match must use atomic_exchange so the first call wins.
    m = re.search(
        r"on_boot_trigger_match\([^{]*\)\s*\{(.*?)^\}",
        src, re.DOTALL | re.MULTILINE,
    )
    assert m, "on_boot_trigger_match body not found"
    body = m.group(1)
    assert "atomic_exchange(&s_boot_triggered, true)" in body
    # Subsequent calls return without effect (no xTaskCreate spawn).
    assert re.search(
        r"atomic_exchange\(&s_boot_triggered, true\)\s*\)\s*return",
        body,
    ), "The guard's exchange-then-return idiom must short-circuit a second match."


def test_c1c_boot_trigger_captures_xtaskcreate_return():
    src = _read("main/usb_cdc.c")
    m = re.search(
        r"on_boot_trigger_match\([^{]*\)\s*\{(.*?)^\}",
        src, re.DOTALL | re.MULTILINE,
    )
    body = m.group(1)
    # No (void) cast on xTaskCreate -- the return must be captured.
    assert "(void)xTaskCreate" not in body
    assert "xTaskCreate(boot_trigger_reset_task" in body
    # Return must be checked.
    assert re.search(r"rc\s*!=\s*pdPASS", body) or "pdFAIL" in body
    # On failure, the guard is reset so a future trigger can retry.
    assert "atomic_store(&s_boot_triggered, false)" in body


def test_c1c_boot_trigger_task_low_priority():
    src = _read("main/usb_cdc.c")
    # Must NOT use configMAX_PRIORITIES anywhere near the boot_trig task.
    m = re.search(
        r"xTaskCreate\s*\(\s*boot_trigger_reset_task[^)]*\)", src,
    )
    assert m, "xTaskCreate for boot_trigger_reset_task not found"
    call = m.group(0)
    assert "configMAX_PRIORITIES" not in call, (
        "boot_trigger_reset_task must run at low priority to avoid "
        "preempting the TinyUSB callback unwind."
    )
    assert "tskIDLE_PRIORITY" in call


def test_c1c_shutdown_handler_register_return_checked():
    src = _read("main/usb_cdc.c")
    # esp_register_shutdown_handler return must be captured (not bare (void)).
    assert "(void)esp_register_shutdown_handler" not in src
    # Either captured into a variable or used in an if.
    assert re.search(
        r"esp_register_shutdown_handler\s*\([^)]*\)\s*;?\s*$",
        src, re.MULTILINE,
    ) is None or "sh_err" in src, (
        "esp_register_shutdown_handler return must be checked and acted on."
    )
