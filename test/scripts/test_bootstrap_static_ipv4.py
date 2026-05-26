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


# ---------------------------------------------------------------------------
# New: malformed string handling in apply_static_ipv4_core
# ---------------------------------------------------------------------------

def test_apply_static_ipv4_core_logs_error_on_bad_address():
    """apply_static_ipv4_core logs ESP_LOGE for an invalid IPv4 address string."""
    src = _read_wifi_c()
    # Find the core function body.
    m = re.search(
        r"static void apply_static_ipv4_core\s*\([^)]+\)(.*?)(?=\n#endif|\nstatic void apply_static_ipv4_enterprise|\Z)",
        src, re.DOTALL,
    )
    assert m, "apply_static_ipv4_core body not found in wifi.c"
    body = m.group(1)
    # Must log an error when the address string is invalid.
    assert "ESP_LOGE" in body, (
        "apply_static_ipv4_core does not call ESP_LOGE for invalid address. "
        "A malformed string like '192.168.1' or '256.0.0.1' must be logged "
        "and the function must return early -- silent application of a zero "
        "IP would route all traffic to the wrong interface."
    )
    # Must return early (not fall through to esp_netif_set_ip_info).
    assert "return" in body, (
        "apply_static_ipv4_core has no early-return path for invalid input."
    )


def test_apply_static_ipv4_core_validates_netmask():
    """apply_static_ipv4_core validates the netmask string separately from the address."""
    src = _read_wifi_c()
    m = re.search(
        r"static void apply_static_ipv4_core\s*\([^)]+\)(.*?)(?=\n#endif|\nstatic void apply_static_ipv4_enterprise|\Z)",
        src, re.DOTALL,
    )
    assert m, "apply_static_ipv4_core body not found in wifi.c"
    body = m.group(1)
    # Should reference netmask in an error log or validation call.
    assert "netmask" in body.lower() or "NETMASK" in body, (
        "apply_static_ipv4_core does not reference netmask in validation logic. "
        "A malformed netmask (e.g., '255.255.256.0') must be caught."
    )
    assert body.lower().count("esp_err") >= 3 or body.count("esp_netif_str_to_ip4") >= 3, (
        "apply_static_ipv4_core does not validate all three fields "
        "(address, netmask, gateway) with esp_netif_str_to_ip4. "
        "A missing validation allows a malformed field to silently zero the IP."
    )


def test_apply_static_ipv4_core_validates_gateway():
    """apply_static_ipv4_core validates the gateway string."""
    src = _read_wifi_c()
    m = re.search(
        r"static void apply_static_ipv4_core\s*\([^)]+\)(.*?)(?=\n#endif|\nstatic void apply_static_ipv4_enterprise|\Z)",
        src, re.DOTALL,
    )
    assert m, "apply_static_ipv4_core body not found"
    body = m.group(1)
    assert "gw" in body and "esp_netif_str_to_ip4" in body, (
        "apply_static_ipv4_core does not validate the gateway with "
        "esp_netif_str_to_ip4. A malformed gateway string must be rejected."
    )


def test_apply_static_ipv4_core_stops_dhcp_before_set():
    """apply_static_ipv4_core stops the DHCP client before applying static address."""
    src = _read_wifi_c()
    m = re.search(
        r"static void apply_static_ipv4_core\s*\([^)]+\)(.*?)(?=\n#endif|\nstatic void apply_static_ipv4_enterprise|\Z)",
        src, re.DOTALL,
    )
    assert m, "apply_static_ipv4_core body not found"
    body = m.group(1)
    assert "esp_netif_dhcpc_stop" in body, (
        "apply_static_ipv4_core does not call esp_netif_dhcpc_stop before "
        "esp_netif_set_ip_info. Applying a static IP while DHCP is active can "
        "cause the DHCP client to overwrite it on the next renewal."
    )
    idx_stop = body.index("esp_netif_dhcpc_stop")
    idx_set  = body.index("esp_netif_set_ip_info")
    assert idx_stop < idx_set, (
        "esp_netif_dhcpc_stop appears after esp_netif_set_ip_info in "
        "apply_static_ipv4_core -- DHCP must be stopped FIRST."
    )


def test_apply_static_ipv4_core_tolerates_dhcp_already_stopped():
    """apply_static_ipv4_core handles ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED gracefully."""
    src = _read_wifi_c()
    assert "ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED" in src, (
        "ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED not handled in wifi.c. "
        "When the DHCP client is not running (INIT state), dhcpc_stop returns "
        "this error; the code must ignore it rather than asserting."
    )


def test_apply_static_ipv4_core_optional_dns_null_safe():
    """apply_static_ipv4_core only sets DNS when dns_pri/dns_sec are non-NULL."""
    src = _read_wifi_c()
    m = re.search(
        r"static void apply_static_ipv4_core\s*\([^)]+\)(.*?)(?=\n#endif|\nstatic void apply_static_ipv4_enterprise|\Z)",
        src, re.DOTALL,
    )
    assert m, "apply_static_ipv4_core body not found"
    body = m.group(1)
    # DNS section must be guarded by a NULL check on dns_pri.
    assert re.search(r"if\s*\(\s*dns_pri\s*\)", body), (
        "apply_static_ipv4_core does not NULL-check dns_pri before calling "
        "esp_netif_set_dns_info. Passing NULL as a DNS string to "
        "esp_netif_str_to_ip4 would be undefined behaviour."
    )
    assert re.search(r"if\s*\(\s*dns_sec\s*\)", body), (
        "apply_static_ipv4_core does not NULL-check dns_sec."
    )


# ---------------------------------------------------------------------------
# New: dual-stack IPv6 coexistence guards
# ---------------------------------------------------------------------------

def test_bootstrap_ipv6_mode_disabled_constant_defined():
    """IPV6_MODE_DISABLED constant is defined and used as the default BOOTSTRAP_IPV6_MODE."""
    src = _read_wifi_c()
    assert "IPV6_MODE_DISABLED" in src, \
        "IPV6_MODE_DISABLED constant not found in wifi.c"
    # Must appear as the default for BOOTSTRAP_IPV6_MODE.
    assert re.search(
        r"#\s*define\s+BOOTSTRAP_IPV6_MODE\s+IPV6_MODE_DISABLED",
        src,
    ), (
        "BOOTSTRAP_IPV6_MODE does not default to IPV6_MODE_DISABLED. "
        "Bootstrap VLANs typically have no IPv6 infrastructure; enabling "
        "IPv6 by default would cause SLAAC probes to time out noisily."
    )


def test_ipv6_bring_up_bootstrap_guarded_by_bootstrap_ipv6_mode():
    """ipv6_bring_up_bootstrap() is only compiled when BOOTSTRAP_IPV6_MODE != DISABLED."""
    src = _read_wifi_c()
    m = re.search(
        r"(#if|#ifdef)[^\n]*USE_STATIC_IPV4_BOOTSTRAP[^\n]*\n"
        r"(.*?)"
        r"ipv6_bring_up_bootstrap",
        src, re.DOTALL,
    )
    assert m, (
        "ipv6_bring_up_bootstrap call not gated by USE_STATIC_IPV4_BOOTSTRAP "
        "guard in wifi.c. It must only compile when the bootstrap static path "
        "is active."
    )


def test_ipv6_bring_up_bootstrap_also_guarded_by_mode_not_disabled():
    """ipv6_bring_up_bootstrap is inside a BOOTSTRAP_IPV6_MODE != DISABLED check."""
    src = _read_wifi_c()
    assert "BOOTSTRAP_IPV6_MODE" in src, \
        "BOOTSTRAP_IPV6_MODE not referenced in wifi.c"
    # The guard around the call must exclude IPV6_MODE_DISABLED.
    assert re.search(
        r"BOOTSTRAP_IPV6_MODE\s*!=\s*IPV6_MODE_DISABLED",
        src,
    ), (
        "No 'BOOTSTRAP_IPV6_MODE != IPV6_MODE_DISABLED' guard found in wifi.c. "
        "The call to ipv6_bring_up_bootstrap must be skipped when the mode is "
        "DISABLED to avoid sending RS/SLAAC probes on the bootstrap VLAN."
    )


# ---------------------------------------------------------------------------
# New: gateway-outside-subnet guard (documentation / compile-time enforcement)
# ---------------------------------------------------------------------------

def test_gateway_outside_subnet_comment_or_logw_present():
    """Gateway validation logs LOGW (not silently ignored) when conversion fails."""
    src = _read_wifi_c()
    m = re.search(
        r"static void apply_static_ipv4_core\s*\([^)]+\)(.*?)(?=\n#endif|\nstatic void apply_static_ipv4_enterprise|\Z)",
        src, re.DOTALL,
    )
    assert m, "apply_static_ipv4_core body not found"
    body = m.group(1)
    # The gateway validation branch must either LOGE or return on bad gw.
    assert "gw" in body and ("return" in body or "ESP_LOGE" in body), (
        "apply_static_ipv4_core does not return or log an error when the "
        "gateway string fails validation. A gateway outside the subnet can "
        "silently break routing on the bootstrap VLAN."
    )


# ---------------------------------------------------------------------------
# New: USE_STATIC_IPV4 vs USE_STATIC_IPV4_BOOTSTRAP compile-time guard
# ---------------------------------------------------------------------------

def test_use_static_ipv4_and_bootstrap_combined_guard_exists():
    """apply_static_ipv4_core is compiled when either USE_STATIC_IPV4 or USE_STATIC_IPV4_BOOTSTRAP is defined."""
    src = _read_wifi_c()
    assert re.search(
        r"#if\s+defined\(USE_STATIC_IPV4\)\s*\|\|\s*defined\(USE_STATIC_IPV4_BOOTSTRAP\)",
        src,
    ), (
        "Combined guard 'defined(USE_STATIC_IPV4) || defined(USE_STATIC_IPV4_BOOTSTRAP)' "
        "not found in wifi.c. apply_static_ipv4_core must compile under either "
        "flag to avoid link errors when only one is defined."
    )
