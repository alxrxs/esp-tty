#!/usr/bin/env python3
"""
test/scripts/test_cert_renewer_reconnect.py
-- Structural assertions for the cert-renewal -> reconnect fix.

After a successful SCEP re-enrollment the cert_renewer task calls
esp_wifi_disconnect() to force the EAP supplicant to redo the 802.1X
handshake with the freshly applied credentials.  esp_wifi_disconnect()
emits WIFI_EVENT_STA_DISCONNECTED with reason=ASSOC_LEAVE (8), and the
wifi.c event handler normally treats that reason as a planned teardown
and refuses to reconnect.  To avoid going permanently offline after a
renewal, cert_renewer.c must set a flag (wifi_signal_eap_creds_rotated)
before calling esp_wifi_disconnect(), and the wifi.c ASSOC_LEAVE branch
must consume that flag and call esp_wifi_connect() instead of skipping.

These tests are pure source-level grep assertions; they run instantly
on the host without any build.
"""

import os
import re

SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR    = os.path.dirname(os.path.dirname(SCRIPT_DIR))
WIFI_C         = os.path.join(PROJECT_DIR, "main", "wifi.c")
WIFI_H         = os.path.join(PROJECT_DIR, "main", "wifi.h")
CERT_RENEWER_C = os.path.join(PROJECT_DIR, "main", "cert_renewer.c")


def _read(p):
    with open(p, "r") as f:
        return f.read()


def test_wifi_h_declares_setter():
    """wifi.h must declare wifi_signal_eap_creds_rotated."""
    src = _read(WIFI_H)
    assert "wifi_signal_eap_creds_rotated" in src, (
        "wifi.h must declare wifi_signal_eap_creds_rotated() so callers "
        "can signal that the next ASSOC_LEAVE is renewal-driven."
    )


def test_wifi_c_defines_flag_and_setter():
    """wifi.c must define the atomic flag and the setter function."""
    src = _read(WIFI_C)
    assert "s_eap_creds_just_rotated" in src, (
        "wifi.c must define s_eap_creds_just_rotated as the cross-task "
        "signal between cert_renewer and the wifi event handler."
    )
    # Must be atomic to be safe between tasks.
    assert re.search(r"_Atomic\s+bool\s+s_eap_creds_just_rotated",
                     src), \
        "s_eap_creds_just_rotated must be _Atomic bool."
    assert re.search(r"void\s+wifi_signal_eap_creds_rotated\s*\(", src), \
        "wifi.c must define wifi_signal_eap_creds_rotated()."


def test_disconnect_handler_consumes_flag_unconditionally():
    """The DISCONNECTED handler must atomic_exchange the flag at the top,
    BEFORE inspecting ev->reason.  H2.C: if the flag were only consumed
    inside the ASSOC_LEAVE branch, a disconnect that surfaces with a
    different reason (RADIUS reject -> AUTH_FAIL, AP went away ->
    BEACON_TIMEOUT, ...) would leak the flag into a later, unrelated
    ASSOC_LEAVE, spuriously triggering the post-renewal reconnect path."""
    src = _read(WIFI_C)
    # Locate the entire disconnect handler.
    m = re.search(
        r"event_id\s*==\s*WIFI_EVENT_STA_DISCONNECTED(.+?)disc_done\s*:",
        src, re.DOTALL)
    assert m, "Could not locate WIFI_EVENT_STA_DISCONNECTED handler"
    body = m.group(1)
    # The atomic_exchange consumption must appear BEFORE the
    # WIFI_REASON_ASSOC_LEAVE check.
    exch = re.search(r"atomic_exchange\(\s*&s_eap_creds_just_rotated", body)
    al = body.find("WIFI_REASON_ASSOC_LEAVE")
    assert exch, "Handler must consume s_eap_creds_just_rotated via atomic_exchange"
    assert al > 0, "ASSOC_LEAVE branch missing from handler"
    assert exch.start() < al, (
        "atomic_exchange(&s_eap_creds_just_rotated) MUST run before the "
        "ASSOC_LEAVE check so the flag is cleared on EVERY disconnect path, "
        "not just the ones that happen to surface as ASSOC_LEAVE."
    )
    # The ASSOC_LEAVE branch should still observe the value and reconnect.
    al_branch = re.search(
        r"if\s*\(\s*ev->reason\s*==\s*WIFI_REASON_ASSOC_LEAVE\s*\).*?disc_done;\s*\}",
        body, re.DOTALL)
    assert al_branch, "Could not locate ASSOC_LEAVE branch"
    al_body = al_branch.group(0)
    assert "rotated_expected" in al_body, (
        "ASSOC_LEAVE branch must check the consumed-flag value to decide "
        "between reconnect and planned-teardown.")
    assert "esp_wifi_connect" in al_body, (
        "ASSOC_LEAVE branch must call esp_wifi_connect() when the flag "
        "was set, otherwise the device stays offline after renewal."
    )


def test_cert_renewer_signals_before_disconnect():
    """cert_renewer must call the setter BEFORE esp_wifi_disconnect()."""
    src = _read(CERT_RENEWER_C)
    # Find the location of both calls.
    # Strip comments so we don't match the function name in doc text.
    src_no_comments = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src_no_comments = re.sub(r"//[^\n]*", "", src_no_comments)
    sig_match = re.search(r"wifi_signal_eap_creds_rotated\s*\(\s*\)\s*;",
                          src_no_comments)
    disc_match = re.search(r"esp_wifi_disconnect\s*\(\s*\)\s*;",
                           src_no_comments)
    assert sig_match, (
        "cert_renewer.c must call wifi_signal_eap_creds_rotated() so the "
        "post-disconnect ASSOC_LEAVE is handled as a reconnect trigger."
    )
    assert disc_match, "cert_renewer.c must still call esp_wifi_disconnect()."
    assert sig_match.start() < disc_match.start(), (
        "wifi_signal_eap_creds_rotated() must be called BEFORE "
        "esp_wifi_disconnect() to avoid a race where the disconnect "
        "event arrives before the flag is set."
    )
