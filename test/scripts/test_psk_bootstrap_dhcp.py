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
