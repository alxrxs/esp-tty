#!/usr/bin/env python3
"""
test/scripts/test_bootstrap_static_ipv4.py
-- Structural guard tests for the bootstrap-network static IPv4 feature.

Grep-asserts that main/wifi.c and main/config.example.h contain the correct
guard structure added for USE_STATIC_IPV4_BOOTSTRAP.  These tests act as
regression guards: if someone accidentally removes or misnames the guards in a
future refactor, the tests catch it before a device is flashed with broken
behaviour.

E2E note: confirming that static IP is actually applied on the bootstrap
network requires a real two-subnet test environment.  That cannot be automated
here; the expected behaviour is documented in the code comments in wifi.c.
"""

import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
WIFI_C = os.path.join(PROJECT_DIR, "main", "wifi.c")
CONFIG_EXAMPLE_H = os.path.join(PROJECT_DIR, "main", "config.example.h")


def _read_wifi_c():
    with open(WIFI_C, "r") as f:
        return f.read()


def _read_config_example_h():
    with open(CONFIG_EXAMPLE_H, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Compile-time sanity check guards
# ---------------------------------------------------------------------------

def test_use_static_ipv4_bootstrap_requires_wifi_enterprise_ssid():
    """USE_STATIC_IPV4_BOOTSTRAP without WIFI_ENTERPRISE_SSID triggers #error."""
    src = _read_wifi_c()
    assert "USE_STATIC_IPV4_BOOTSTRAP" in src, \
        "USE_STATIC_IPV4_BOOTSTRAP not referenced in wifi.c"
    # The guard must pair USE_STATIC_IPV4_BOOTSTRAP with !WIFI_ENTERPRISE_SSID.
    assert re.search(
        r"defined\(USE_STATIC_IPV4_BOOTSTRAP\)\s*&&\s*!defined\(WIFI_ENTERPRISE_SSID\)",
        src,
    ), "Missing guard: USE_STATIC_IPV4_BOOTSTRAP requires WIFI_ENTERPRISE_SSID"


def test_bootstrap_static_ipv4_address_macro_guard():
    """#error fires when BOOTSTRAP_STATIC_IPV4_ADDRESS is missing."""
    src = _read_wifi_c()
    assert "BOOTSTRAP_STATIC_IPV4_ADDRESS" in src, \
        "BOOTSTRAP_STATIC_IPV4_ADDRESS not referenced in wifi.c"
    assert re.search(
        r'#\s*error\s+"USE_STATIC_IPV4_BOOTSTRAP requires BOOTSTRAP_STATIC_IPV4_ADDRESS',
        src,
    ), "Missing #error guard for BOOTSTRAP_STATIC_IPV4_ADDRESS"


def test_bootstrap_static_ipv4_netmask_macro_guard():
    """#error fires when BOOTSTRAP_STATIC_IPV4_NETMASK is missing."""
    src = _read_wifi_c()
    assert re.search(
        r'#\s*error\s+"USE_STATIC_IPV4_BOOTSTRAP requires BOOTSTRAP_STATIC_IPV4_NETMASK',
        src,
    ), "Missing #error guard for BOOTSTRAP_STATIC_IPV4_NETMASK"


def test_bootstrap_static_ipv4_gateway_macro_guard():
    """#error fires when BOOTSTRAP_STATIC_IPV4_GATEWAY is missing."""
    src = _read_wifi_c()
    assert re.search(
        r'#\s*error\s+"USE_STATIC_IPV4_BOOTSTRAP requires BOOTSTRAP_STATIC_IPV4_GATEWAY',
        src,
    ), "Missing #error guard for BOOTSTRAP_STATIC_IPV4_GATEWAY"


def test_bootstrap_ipv6_mode_defaults_to_disabled():
    """BOOTSTRAP_IPV6_MODE defaults to IPV6_MODE_DISABLED when not user-defined."""
    src = _read_wifi_c()
    assert re.search(
        r"#\s*ifndef\s+BOOTSTRAP_IPV6_MODE\s*\n"
        r"\s*#\s*define\s+BOOTSTRAP_IPV6_MODE\s+IPV6_MODE_DISABLED",
        src,
    ), "BOOTSTRAP_IPV6_MODE does not default to IPV6_MODE_DISABLED"


def test_bootstrap_static_ipv6_address_guard_under_ipv6_static():
    """#error guard for BOOTSTRAP_STATIC_IPV6_ADDRESS is nested under IPV6_MODE_STATIC."""
    src = _read_wifi_c()
    assert "BOOTSTRAP_STATIC_IPV6_ADDRESS" in src, \
        "BOOTSTRAP_STATIC_IPV6_ADDRESS not referenced in wifi.c"
    assert re.search(
        r'#\s*error\s+"BOOTSTRAP_IPV6_MODE==IPV6_MODE_STATIC requires BOOTSTRAP_STATIC_IPV6_ADDRESS',
        src,
    ), "Missing #error guard for BOOTSTRAP_STATIC_IPV6_ADDRESS"


# ---------------------------------------------------------------------------
# apply_static_ipv4_bootstrap() function
# ---------------------------------------------------------------------------

def test_apply_static_ipv4_bootstrap_function_exists():
    """apply_static_ipv4_bootstrap() is defined in wifi.c."""
    src = _read_wifi_c()
    assert "apply_static_ipv4_bootstrap" in src, \
        "apply_static_ipv4_bootstrap not found in wifi.c"
    assert re.search(r"static void apply_static_ipv4_bootstrap\(void\)", src), \
        "apply_static_ipv4_bootstrap() signature not found"


def test_apply_static_ipv4_enterprise_function_exists():
    """apply_static_ipv4_enterprise() is defined in wifi.c (renamed from apply_static_ipv4)."""
    src = _read_wifi_c()
    assert "apply_static_ipv4_enterprise" in src, \
        "apply_static_ipv4_enterprise not found in wifi.c"
    assert re.search(r"static void apply_static_ipv4_enterprise\(void\)", src), \
        "apply_static_ipv4_enterprise() signature not found"


def test_apply_static_ipv4_core_function_exists():
    """apply_static_ipv4_core() accepts addr/netmask/gw/dns_pri/dns_sec parameters."""
    src = _read_wifi_c()
    assert re.search(
        r"static void apply_static_ipv4_core\s*\(",
        src,
    ), "apply_static_ipv4_core() not found in wifi.c"
    # Must take at least five parameters (addr, netmask, gw, dns_pri, dns_sec)
    match = re.search(
        r"static void apply_static_ipv4_core\s*\(([^)]+)\)",
        src,
    )
    assert match, "apply_static_ipv4_core() parameter list not parseable"
    params = match.group(1)
    assert params.count(",") >= 4, \
        "apply_static_ipv4_core() expected at least 5 parameters"


# ---------------------------------------------------------------------------
# WIFI_EVENT_STA_CONNECTED event handler branch
# ---------------------------------------------------------------------------

def test_sta_connected_handler_has_bootstrap_static_branch():
    """STA_CONNECTED handler contains USE_STATIC_IPV4_BOOTSTRAP branch."""
    src = _read_wifi_c()
    # The bootstrap static branch must call apply_static_ipv4_bootstrap()
    assert "apply_static_ipv4_bootstrap()" in src, \
        "apply_static_ipv4_bootstrap() not called in wifi.c"
    # The fallback DHCP branch must still be present
    assert "esp_netif_dhcpc_start(s_sta_netif)" in src, \
        "esp_netif_dhcpc_start fallback not found in wifi.c"


def test_sta_connected_handler_uses_enterprise_wrapper():
    """STA_CONNECTED handler calls apply_static_ipv4_enterprise(), not the old apply_static_ipv4()."""
    src = _read_wifi_c()
    assert "apply_static_ipv4_enterprise()" in src, \
        "apply_static_ipv4_enterprise() not called in wifi.c"
    # Old bare name must no longer be called directly (as a standalone call)
    assert not re.search(r"\bapply_static_ipv4\(\)", src), \
        "Old bare apply_static_ipv4() call still present -- should use wrappers"


# ---------------------------------------------------------------------------
# IP_EVENT_STA_GOT_IP handler goto guard
# ---------------------------------------------------------------------------

def test_ip_event_got_ip_skips_bootstrap_static_path():
    """IP_EVENT_STA_GOT_IP skips signalling when bootstrap static path handled it."""
    src = _read_wifi_c()
    # The goto guard expression must cover USE_STATIC_IPV4_BOOTSTRAP
    assert "USE_STATIC_IPV4_BOOTSTRAP" in src, \
        "USE_STATIC_IPV4_BOOTSTRAP not referenced near ip_event_done goto"
    # Verify ip_event_done label still exists
    assert "ip_event_done:" in src, \
        "ip_event_done label not found in wifi.c"


# ---------------------------------------------------------------------------
# ipv6_bring_up_bootstrap()
# ---------------------------------------------------------------------------

def test_ipv6_bring_up_bootstrap_function_exists():
    """ipv6_bring_up_bootstrap() is compiled under USE_STATIC_IPV4_BOOTSTRAP guard."""
    src = _read_wifi_c()
    assert "ipv6_bring_up_bootstrap" in src, \
        "ipv6_bring_up_bootstrap not found in wifi.c"
    # Must be guarded by USE_STATIC_IPV4_BOOTSTRAP
    assert re.search(
        r"defined\(USE_STATIC_IPV4_BOOTSTRAP\)",
        src,
    ), "ipv6_bring_up_bootstrap not guarded by USE_STATIC_IPV4_BOOTSTRAP"


# ---------------------------------------------------------------------------
# config.example.h documentation
# ---------------------------------------------------------------------------

def test_config_example_documents_use_static_ipv4_bootstrap():
    """config.example.h has a USE_STATIC_IPV4_BOOTSTRAP section."""
    src = _read_config_example_h()
    assert "USE_STATIC_IPV4_BOOTSTRAP" in src, \
        "USE_STATIC_IPV4_BOOTSTRAP not documented in config.example.h"
    assert "BOOTSTRAP_STATIC_IPV4_ADDRESS" in src, \
        "BOOTSTRAP_STATIC_IPV4_ADDRESS not documented in config.example.h"


def test_config_example_documents_bootstrap_ipv6_mode():
    """config.example.h has a BOOTSTRAP_IPV6_MODE section."""
    src = _read_config_example_h()
    assert "BOOTSTRAP_IPV6_MODE" in src, \
        "BOOTSTRAP_IPV6_MODE not documented in config.example.h"
    assert "BOOTSTRAP_STATIC_IPV6_ADDRESS" in src, \
        "BOOTSTRAP_STATIC_IPV6_ADDRESS not documented in config.example.h"
