"""
test_round3_medium_m2.py -- structural pytests for round-3 MEDIUM fixes (M2.A..M2.F)

Each test grep-asserts an invariant in the relevant source file so a
regression is caught at commit time rather than at runtime on hardware.
"""

import re
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def _read(rel):
    with open(os.path.join(PROJECT_ROOT, rel)) as f:
        return f.read()


# ---------------------------------------------------------------------------
# M2.A -- boot_trigger_reset_task stack bumped to 8192 bytes
# ---------------------------------------------------------------------------

def test_m2a_boot_trigger_task_stack_8192():
    src = _read("main/usb_cdc.c")
    # Find the xTaskCreate call for boot_trigger_reset_task and confirm
    # the stack parameter is 8192.
    m = re.search(
        r"xTaskCreate\s*\(\s*boot_trigger_reset_task\s*,"
        r"[^,]*,\s*(\d+)\s*,",
        src,
    )
    assert m, "xTaskCreate(boot_trigger_reset_task, ...) not found in usb_cdc.c"
    stack = int(m.group(1))
    assert stack >= 8192, (
        f"boot_trigger_reset_task stack must be >= 8192 bytes (got {stack}). "
        "tinyusb_driver_uninstall() + esp_restart() combined frame depth can "
        "approach 4 KB; a 4096-byte stack overflows silently.  See M2.A."
    )


# ---------------------------------------------------------------------------
# M2.B -- pump count replaces bool; teardown takes exactly the right number
# ---------------------------------------------------------------------------

def test_m2b_pump_count_replaces_pumps_running():
    src = _read("main/ssh_server.c")
    # The old boolean must be gone.
    assert "s_pumps_running" not in src, (
        "s_pumps_running (bool) must be replaced by s_pump_count (int). "
        "See M2.B."
    )
    # The new count variable must exist.
    assert "s_pump_count" in src, (
        "s_pump_count must be declared in ssh_server.c.  See M2.B."
    )


def test_m2b_teardown_loops_over_pump_count():
    src = _read("main/ssh_server.c")
    # teardown must iterate s_pump_count times, not hard-code two takes.
    assert re.search(r"for\s*\(.*s_pump_count.*\)", src), (
        "teardown_active_session must loop exactly s_pump_count times over "
        "xSemaphoreTake(s_pump_done_sem).  See M2.B."
    )


def test_m2b_partial_failure_sets_pump_count_1():
    src = _read("main/ssh_server.c")
    # When only rc_a2b succeeded, s_pump_count must be set to 1.
    assert "s_pump_count = 1" in src, (
        "Partial-failure path (only a2b started) must set s_pump_count = 1 "
        "so teardown waits for exactly one semaphore give.  See M2.B."
    )


def test_m2b_both_pumps_sets_pump_count_2():
    src = _read("main/ssh_server.c")
    # Normal path: both pumps created -> count = 2.
    assert "s_pump_count = 2" in src, (
        "Normal path (both pumps created) must set s_pump_count = 2. "
        "See M2.B."
    )


# ---------------------------------------------------------------------------
# M2.C -- stale comment about direct esp_restart is rewritten
# ---------------------------------------------------------------------------

def test_m2c_no_stale_does_not_return_comment():
    src = _read("main/usb_cdc.c")
    # The old comment claimed the callback "intentionally does not return".
    # That was true of the original direct-call design; the current design
    # defers work to a background task and returns normally.
    assert "Intentionally does not return" not in src, (
        "The stale 'Intentionally does not return -- esp_restart() never "
        "returns' comment must be removed; the on_boot_trigger_match callback "
        "now spawns a task and returns normally.  See M2.C."
    )


def test_m2c_comment_references_shutdown_handler():
    src = _read("main/usb_cdc.c")
    # The new comment must explain the deferred shutdown-handler mechanism.
    assert "esp_register_shutdown_handler" in src, (
        "usb_cdc.c must document the esp_register_shutdown_handler mechanism "
        "used by boot_trigger_reset_task.  See M2.C."
    )


# ---------------------------------------------------------------------------
# M2.D -- duplicate freertos/FreeRTOS.h include removed
# ---------------------------------------------------------------------------

def test_m2d_no_duplicate_freertos_include():
    src = _read("main/usb_cdc.c")
    count = src.count('#include "freertos/FreeRTOS.h"')
    assert count <= 1, (
        f"usb_cdc.c has {count} copies of #include \"freertos/FreeRTOS.h\"; "
        "the duplicate (with stale portDISABLE_INTERRUPTS comment) must be "
        "removed.  See M2.D."
    )


def test_m2d_no_port_disable_interrupts_comment():
    src = _read("main/usb_cdc.c")
    assert "portDISABLE_INTERRUPTS" not in src, (
        "The stale portDISABLE_INTERRUPTS comment must be removed together "
        "with the duplicate FreeRTOS include.  See M2.D."
    )


# ---------------------------------------------------------------------------
# M2.E -- unreachable vTaskDelete after esp_restart replaced with comment
# ---------------------------------------------------------------------------

def test_m2e_no_vtaskdelete_after_esp_restart_in_boot_trigger():
    src = _read("main/usb_cdc.c")
    # Isolate the boot_trigger_reset_task body.
    m = re.search(
        r"boot_trigger_reset_task\s*\([^)]*\)\s*\{(.*?)^\}",
        src,
        re.DOTALL | re.MULTILINE,
    )
    assert m, "boot_trigger_reset_task body not found in usb_cdc.c"
    body = m.group(1)
    # esp_restart() must be present.
    assert "esp_restart()" in body, "boot_trigger_reset_task must call esp_restart()"
    # vTaskDelete must NOT appear after esp_restart -- it is dead code.
    restart_idx = body.find("esp_restart()")
    vtask_idx = body.find("vTaskDelete", restart_idx)
    assert vtask_idx == -1, (
        "vTaskDelete(NULL) after esp_restart() is unreachable dead code. "
        "Replace it with a comment annotation.  See M2.E."
    )
    # An unreachable annotation comment must be present instead.
    assert "unreachable" in body[restart_idx:], (
        "An '// unreachable' comment must follow esp_restart() to document "
        "the non-return property for static analysers.  See M2.E."
    )


# ---------------------------------------------------------------------------
# M2.F -- no time(NULL) deadline arithmetic in ssh_server.c
# ---------------------------------------------------------------------------

def test_m2f_no_time_null_deadline_arithmetic():
    src = _read("main/ssh_server.c")
    # Find every occurrence of time(NULL) in non-comment lines.
    code_lines = [
        line for line in src.splitlines()
        if "time(NULL)" in line and not line.lstrip().startswith("*")
        and not line.lstrip().startswith("//")
    ]
    for line in code_lines:
        # A log-timestamp use of time(NULL) is acceptable (read-only display).
        # Deadline arithmetic would combine time(NULL) with +, -, deadline_us,
        # timeout, etc.  Flag any non-display use.
        assert re.search(r"(printf|log|ESP_LOG|snprintf|strftime)", line), (
            f"Possible time(NULL) deadline arithmetic found in ssh_server.c: "
            f"{line.strip()!r}\n"
            "Convert to esp_timer_get_time() or xTaskGetTickCount().  See M2.F."
        )


def test_m2f_handshake_deadline_uses_esp_timer():
    src = _read("main/ssh_server.c")
    # The handshake deadline must use esp_timer_get_time(), not time(NULL).
    assert "esp_timer_get_time()" in src, (
        "The SSH handshake deadline must use esp_timer_get_time() "
        "(monotonic, immune to NTP jumps).  See M2.F / finding H1.C."
    )
    # Confirm the deadline is computed correctly.
    assert "deadline_us" in src, (
        "The handshake deadline variable 'deadline_us' must be present; "
        "it gates the wolfSSH_accept() retry loop.  See M2.F."
    )
