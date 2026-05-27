#!/usr/bin/env python3
"""
test/scripts/test_wifi_backoff_structure.py
-- Structural guards for the H2 wave-2 fixes in main/wifi.c.

Asserts the code shape that the four production-mandated fixes require:

  H2.A: the security_fail classifier is delegated to the pure helper
        wifi_backoff_is_security_failure() (no inline switch).
  H2.B: the disconnect handler no longer calls vTaskDelay() inline; it
        defers the reconnect to s_reconnect_timer via
        reconnect_timer_schedule().
  H2.C: s_eap_creds_just_rotated is consumed UNCONDITIONALLY at the start
        of the disconnect handler -- the atomic_exchange() lives outside
        the ASSOC_LEAVE branch, so it runs for every disconnect.
  H2.D: the backoff math uses wifi_backoff_compute_ms() rather than the
        underflow-by-design (rand % 2W) - W expression.

These run instantly on the host with no hardware or build needed.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
WIFI_C = os.path.join(PROJECT_DIR, "main", "wifi.c")
BACKOFF_H = os.path.join(PROJECT_DIR, "lib", "wifi_backoff", "wifi_backoff.h")
BACKOFF_C = os.path.join(PROJECT_DIR, "lib", "wifi_backoff", "wifi_backoff.c")


def _read(p):
    with open(p, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# H2.A -- security-fail classifier exists in the helper and covers all the
# reason codes the audit flagged.
# ---------------------------------------------------------------------------

REQUIRED_SECURITY_REASONS = {
    14: "MIC_FAILURE",
    15: "4WAY_HANDSHAKE_TIMEOUT",
    16: "GROUP_KEY_UPDATE_TIMEOUT",
    17: "IE_IN_4WAY_DIFFERS",
    18: "GROUP_CIPHER_INVALID",
    19: "PAIRWISE_CIPHER_INVALID",
    20: "AKMP_INVALID",
    23: "802_1X_AUTH_FAILED",
    24: "CIPHER_SUITE_REJECTED",
    202: "AUTH_FAIL",
    203: "ASSOC_FAIL",
    204: "HANDSHAKE_TIMEOUT",
}


def test_wifi_backoff_helper_files_exist():
    assert os.path.isfile(BACKOFF_H), "lib/wifi_backoff/wifi_backoff.h is missing"
    assert os.path.isfile(BACKOFF_C), "lib/wifi_backoff/wifi_backoff.c is missing"


def test_security_classifier_covers_h2a_codes():
    src = _read(BACKOFF_C)
    # Find the body of wifi_backoff_is_security_failure
    m = re.search(
        r"bool\s+wifi_backoff_is_security_failure[^{]*\{(.+?)\n\}\n",
        src, re.S)
    assert m, "wifi_backoff_is_security_failure body not found in wifi_backoff.c"
    body = m.group(1)
    for code, name in REQUIRED_SECURITY_REASONS.items():
        # Match `case <code>:` exactly (word boundary on the number).
        assert re.search(rf"case\s+{code}\s*:", body), (
            f"reason {code} ({name}) is not classified as security failure")


def test_wifi_c_delegates_to_helper():
    src = _read(WIFI_C)
    # The header is included.
    assert '#include "wifi_backoff.h"' in src, (
        "wifi.c does not include wifi_backoff.h")
    # The classifier is called from the disconnect handler.
    assert "wifi_backoff_is_security_failure(ev->reason)" in src, (
        "wifi.c does not use the wifi_backoff classifier in the disconnect "
        "handler")
    # The old inline switch on AUTH_FAIL / HANDSHAKE_TIMEOUT etc must be gone.
    assert "case WIFI_REASON_AUTH_FAIL:" not in src, (
        "wifi.c still contains the inline security_fail switch -- delete it")


# ---------------------------------------------------------------------------
# H2.B -- no inline vTaskDelay in the disconnect path; reconnect timer used.
# ---------------------------------------------------------------------------

def test_no_vtaskdelay_inside_disconnect_handler():
    src = _read(WIFI_C)
    # Extract from "WIFI_EVENT_STA_DISCONNECTED" up to "disc_done:".
    m = re.search(
        r"event_id\s*==\s*WIFI_EVENT_STA_DISCONNECTED.*?disc_done\s*:",
        src, re.S)
    assert m, "could not locate WIFI_EVENT_STA_DISCONNECTED handler"
    block = m.group(0)
    assert "vTaskDelay(" not in block, (
        "vTaskDelay() found inside the WIFI_EVENT_STA_DISCONNECTED handler -- "
        "it blocks the system event task. Use reconnect_timer_schedule.")


def test_reconnect_timer_infra_present():
    src = _read(WIFI_C)
    for sym in (
        "s_reconnect_timer",
        "reconnect_timer_cb",
        "reconnect_timer_schedule",
        "reconnect_timer_cancel",
        "reconnect_timer_create_once",
    ):
        assert sym in src, f"wifi.c is missing reconnect-timer symbol: {sym}"


def test_reconnect_timer_cancelled_on_success():
    """Cancel the deferred reconnect when L2 comes back up, so a stale
    fire from a prior backoff doesn't bounce us."""
    src = _read(WIFI_C)
    m = re.search(
        r"event_id\s*==\s*WIFI_EVENT_STA_CONNECTED(.+?)WIFI_EVENT_STA_DISCONNECTED",
        src, re.S)
    assert m, "could not locate WIFI_EVENT_STA_CONNECTED branch"
    block = m.group(1)
    assert "reconnect_timer_cancel" in block, (
        "WIFI_EVENT_STA_CONNECTED should cancel any pending reconnect timer")


# ---------------------------------------------------------------------------
# H2.C -- s_eap_creds_just_rotated is consumed unconditionally.
# ---------------------------------------------------------------------------

def test_eap_creds_flag_consumed_outside_assoc_leave_branch():
    src = _read(WIFI_C)
    m = re.search(
        r"event_id\s*==\s*WIFI_EVENT_STA_DISCONNECTED.*?disc_done\s*:",
        src, re.S)
    assert m, "could not locate WIFI_EVENT_STA_DISCONNECTED handler"
    block = m.group(0)
    # Find the atomic_exchange call on the flag.
    exch_pos = block.find("atomic_exchange(\n                &s_eap_creds_just_rotated")
    if exch_pos < 0:
        # Allow either formatting style.
        exch_pos_m = re.search(
            r"atomic_exchange\(\s*&s_eap_creds_just_rotated", block)
        assert exch_pos_m, (
            "s_eap_creds_just_rotated is never consumed via atomic_exchange")
        exch_pos = exch_pos_m.start()
    # Find the start of the ASSOC_LEAVE branch.
    al_pos = block.find("WIFI_REASON_ASSOC_LEAVE")
    assert al_pos > 0, "no ASSOC_LEAVE branch found"
    assert exch_pos < al_pos, (
        "s_eap_creds_just_rotated must be consumed BEFORE the ASSOC_LEAVE "
        "branch test so the flag is cleared on every disconnect path -- not "
        "only the ones that happen to reach reason=ASSOC_LEAVE.  Otherwise the "
        "flag leaks and fires spuriously on a later, unrelated ASSOC_LEAVE.")


# ---------------------------------------------------------------------------
# H2.D -- jitter no longer uses the (rand % 2W) - W unsigned-underflow trick.
# ---------------------------------------------------------------------------

def test_no_unsigned_jitter_underflow_in_wifi_c():
    src = _read(WIFI_C)
    # The bad pattern: `(esp_random() % (2u * jitter_window)) - jitter_window`
    bad = re.search(
        r"\(\s*esp_random\(\)\s*%\s*\(\s*2u?\s*\*\s*jitter_window\s*\)\s*\)\s*-\s*jitter_window",
        src)
    assert bad is None, (
        "wifi.c still contains the (rand %% 2W) - W unsigned-underflow jitter "
        "expression. Move it to wifi_backoff_compute_ms which uses signed "
        "arithmetic.")


def test_wifi_c_uses_backoff_compute_helper():
    src = _read(WIFI_C)
    assert "wifi_backoff_compute_ms(" in src, (
        "wifi.c is not calling wifi_backoff_compute_ms() -- jitter math must "
        "live in the pure, unit-testable helper")


def test_backoff_compute_uses_signed_jitter():
    src = _read(BACKOFF_C)
    assert "int32_t jitter_signed" in src, (
        "wifi_backoff.c jitter is not computed in signed arithmetic -- "
        "the underflow-by-design pattern is fragile and the audit flagged it")
