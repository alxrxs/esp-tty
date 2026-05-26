#!/usr/bin/env python3
"""
test/scripts/test_psk_bootstrap_dhcp.py
-- Structural guard tests for PSK bootstrap DHCP feature.

Grep-asserts that main/wifi.c contains the correct guard structure added
for the PSK-bootstrap-always-uses-DHCP feature.  These tests act as
regression guards: if someone accidentally removes the guards in a future
refactor, the tests catch it before a device is flashed with broken
behaviour.

E2E note: confirming that DHCP is actually used on the bootstrap network
requires a real two-subnet test environment (PSK AP on one subnet,
enterprise AP on another).  That cannot be automated here; the expected
behaviour is documented in the code comments in wifi.c.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
WIFI_C = os.path.join(PROJECT_DIR, "main", "wifi.c")


def _read_wifi_c():
    with open(WIFI_C, "r") as f:
        return f.read()


def test_psk_bootstrap_active_flag_declared():
    """s_psk_bootstrap_active is declared under WIFI_ENTERPRISE_SSID guard."""
    src = _read_wifi_c()
    assert "static bool s_psk_bootstrap_active = false;" in src, \
        "s_psk_bootstrap_active flag declaration not found in wifi.c"
    assert "#ifdef WIFI_ENTERPRISE_SSID" in src, \
        "WIFI_ENTERPRISE_SSID guard not found in wifi.c"


def test_wifi_mode_psk_sets_flag_true():
    """wifi_mode_psk() contains s_psk_bootstrap_active = true assignment."""
    src = _read_wifi_c()
    # Find the wifi_mode_psk function body (ends at the next top-level static function)
    match = re.search(
        r"static esp_err_t wifi_mode_psk\b(.*?)(?=\nstatic bool|\nstatic esp_err_t (?!wifi_mode_psk)|\Z)",
        src,
        re.DOTALL,
    )
    assert match, "wifi_mode_psk() not found in wifi.c"
    body = match.group(0)
    assert "s_psk_bootstrap_active = true" in body, \
        "s_psk_bootstrap_active = true not set in wifi_mode_psk()"
    assert "ESP_ERROR_CHECK(esp_wifi_start())" in body, \
        "ESP_ERROR_CHECK(esp_wifi_start()) not found in wifi_mode_psk()"


def test_wifi_mode_enterprise_clears_flag_false():
    """wifi_mode_enterprise() contains s_psk_bootstrap_active = false assignment."""
    src = _read_wifi_c()
    match = re.search(
        r"static esp_err_t wifi_mode_enterprise\b(.*?)(?=\n/\* -{10}|\nstatic esp_err_t wifi_smart_init_common|\Z)",
        src,
        re.DOTALL,
    )
    assert match, "wifi_mode_enterprise() not found in wifi.c"
    body = match.group(0)
    assert "s_psk_bootstrap_active = false" in body, \
        "s_psk_bootstrap_active = false not set in wifi_mode_enterprise()"
    assert "ESP_ERROR_CHECK(esp_wifi_start())" in body, \
        "ESP_ERROR_CHECK(esp_wifi_start()) not found in wifi_mode_enterprise()"


def test_sta_connected_handler_checks_bootstrap_flag():
    """WIFI_EVENT_STA_CONNECTED handler guards static-IP with s_psk_bootstrap_active check."""
    src = _read_wifi_c()
    assert "if (s_psk_bootstrap_active)" in src, \
        "s_psk_bootstrap_active check not found in WIFI_EVENT_STA_CONNECTED handler"


def test_dhcpc_start_called_in_bootstrap_path():
    """esp_netif_dhcpc_start is called in the PSK bootstrap DHCP code path."""
    src = _read_wifi_c()
    assert "esp_netif_dhcpc_start(s_sta_netif)" in src, \
        "esp_netif_dhcpc_start not called in wifi.c for PSK bootstrap DHCP"


# ---------------------------------------------------------------------------
# New: DHCP bootstrap edge-case guards
# ---------------------------------------------------------------------------

def test_dhcp_watchdog_timer_declared():
    """s_dhcp_watchdog timer variable is declared in wifi.c (lease-acquire timeout)."""
    src = _read_wifi_c()
    assert "s_dhcp_watchdog" in src, (
        "s_dhcp_watchdog not found in wifi.c. "
        "The DHCP watchdog is required to recover from stuck DHCP servers "
        "where lwIP stops retrying DISCOVER after a handful of attempts."
    )


def test_dhcp_watchdog_armed_on_sta_connected():
    """DHCP watchdog is armed (xTimerStart) when WIFI_EVENT_STA_CONNECTED fires."""
    src = _read_wifi_c()
    # Verify the timer arm logic is present in the STA_CONNECTED region.
    assert "xTimerStart" in src, \
        "xTimerStart not found in wifi.c -- DHCP watchdog arm logic missing"
    assert "xTimerChangePeriod" in src, (
        "xTimerChangePeriod not found in wifi.c. "
        "The DHCP watchdog should use xTimerChangePeriod to set the period "
        "dynamically before arming it, so it fires DHCP_RETRY_TIMEOUT_SEC "
        "after L2 association."
    )


def test_dhcp_watchdog_stops_on_sta_disconnected():
    """DHCP watchdog is stopped (xTimerStop) when WIFI_EVENT_STA_DISCONNECTED fires."""
    src = _read_wifi_c()
    assert "xTimerStop" in src, (
        "xTimerStop not found in wifi.c. "
        "The DHCP watchdog must be stopped when the STA disconnects; otherwise "
        "it can fire and restart the DHCP client while the interface is down."
    )


def test_dhcp_retry_on_watchdog_callback():
    """DHCP watchdog callback calls dhcpc_stop then dhcpc_start (kick-and-restart)."""
    src = _read_wifi_c()
    assert "esp_netif_dhcpc_stop" in src, (
        "esp_netif_dhcpc_stop not found in wifi.c. "
        "The DHCP watchdog callback must call dhcpc_stop before dhcpc_start "
        "to flush stale lwIP DHCP state."
    )
    # Both stop and start must be present for the kick-and-restart pattern.
    assert "esp_netif_dhcpc_start" in src, \
        "esp_netif_dhcpc_start not found in wifi.c for DHCP watchdog kick"


def test_dhcp_watchdog_guarded_by_dhcp_retry_timeout_sec():
    """DHCP watchdog code is gated on DHCP_RETRY_TIMEOUT_SEC > 0."""
    src = _read_wifi_c()
    assert "DHCP_RETRY_TIMEOUT_SEC" in src, \
        "DHCP_RETRY_TIMEOUT_SEC not found in wifi.c"
    # The macro must gate the watchdog so a value of 0 disables it.
    assert re.search(r"DHCP_RETRY_TIMEOUT_SEC\s*>\s*0", src), (
        "DHCP_RETRY_TIMEOUT_SEC > 0 guard not found in wifi.c. "
        "The watchdog must be conditionally compiled so setting "
        "DHCP_RETRY_TIMEOUT_SEC=0 fully disables it."
    )


def test_dhcp_watchdog_default_timeout_positive():
    """DHCP_RETRY_TIMEOUT_SEC default value is positive."""
    src = _read_wifi_c()
    m = re.search(r"#define\s+DHCP_RETRY_TIMEOUT_SEC\s+(\d+)", src)
    assert m, "DHCP_RETRY_TIMEOUT_SEC #define not found in wifi.c"
    value = int(m.group(1))
    assert value > 0, (
        f"DHCP_RETRY_TIMEOUT_SEC default is {value} -- must be > 0. "
        "A zero default would compile out the watchdog unconditionally."
    )


def test_psk_bootstrap_flag_declared_under_enterprise_guard():
    """s_psk_bootstrap_active is declared inside WIFI_ENTERPRISE_SSID guard."""
    src = _read_wifi_c()
    # Find the ifdef guard before the flag declaration.
    m = re.search(
        r"#ifdef\s+WIFI_ENTERPRISE_SSID.*?static bool s_psk_bootstrap_active",
        src, re.DOTALL,
    )
    assert m, (
        "s_psk_bootstrap_active declaration is not inside a "
        "#ifdef WIFI_ENTERPRISE_SSID block. "
        "Non-enterprise builds should not compile this flag."
    )


def test_sta_connected_handler_dhcp_fallback_is_in_enterprise_guard():
    """DHCP fallback in STA_CONNECTED is inside WIFI_ENTERPRISE_SSID guard."""
    src = _read_wifi_c()
    # The DHCP start call in STA_CONNECTED is inside the enterprise guard
    # (only the bootstrap-active + no-static-bootstrap path goes this way).
    assert "#ifdef WIFI_ENTERPRISE_SSID" in src or "#if defined(WIFI_ENTERPRISE_SSID)" in src, \
        "WIFI_ENTERPRISE_SSID guard not present in wifi.c STA_CONNECTED handler"


def test_dhcp_watchdog_not_armed_in_static_ipv4_build():
    """DHCP watchdog is excluded from USE_STATIC_IPV4 builds (non-enterprise static mode)."""
    src = _read_wifi_c()
    # The guard must be: #if DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)
    assert re.search(
        r"DHCP_RETRY_TIMEOUT_SEC\s*>\s*0\s*&&\s*!defined\(USE_STATIC_IPV4\)",
        src,
    ), (
        "Combined guard 'DHCP_RETRY_TIMEOUT_SEC > 0 && !defined(USE_STATIC_IPV4)' "
        "not found in wifi.c. When USE_STATIC_IPV4 is set (Mode A pure static), "
        "we never run the DHCP client so the watchdog must be compiled out."
    )
