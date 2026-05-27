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


def test_assoc_leave_branch_consumes_flag():
    """The ASSOC_LEAVE event branch must consume the flag and reconnect."""
    src = _read(WIFI_C)
    # Extract the ASSOC_LEAVE handler block (roughly: from the if line up
    # to the closing brace + 'goto disc_done' that signals fall-through).
    m = re.search(
        r"if\s*\(\s*ev->reason\s*==\s*WIFI_REASON_ASSOC_LEAVE\s*\)\s*\{"
        r"(.*?)goto\s+disc_done;\s*\}",
        src, re.DOTALL)
    assert m, "Could not locate ASSOC_LEAVE branch in wifi.c"
    body = m.group(1)
    assert "s_eap_creds_just_rotated" in body, (
        "ASSOC_LEAVE branch must inspect s_eap_creds_just_rotated."
    )
    assert "atomic_exchange" in body, (
        "ASSOC_LEAVE branch must atomic_exchange the flag (read+clear)."
    )
    assert "esp_wifi_connect" in body, (
        "ASSOC_LEAVE branch must call esp_wifi_connect() when the flag "
        "is set, otherwise the device stays offline after renewal."
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
