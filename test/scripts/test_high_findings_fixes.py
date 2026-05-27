"""
test_high_findings_fixes.py -- structural pytests for the 7 HIGH-finding fixes
(A1..A7).  Each test grep-asserts an invariant in the relevant source file so
regressions are caught at commit time, not at runtime on the device.
"""

import os
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def _read(rel):
    with open(os.path.join(PROJECT_ROOT, rel)) as f:
        return f.read()


# ---------------------------------------------------------------------------
# A1 -- wolfSSH_accept retry handles WS_WANT_WRITE as well as WS_WANT_READ
# ---------------------------------------------------------------------------

def test_a1_accept_retry_handles_want_write():
    src = _read("main/ssh_server.c")
    # The do/while loop must reference both WANT codes.
    assert "WS_WANT_READ" in src and "WS_WANT_WRITE" in src, (
        "wolfSSH_accept retry loop must handle both WS_WANT_READ and "
        "WS_WANT_WRITE -- handshake on slow links returns WANT_WRITE when "
        "the outbound buffer is full."
    )
    # Specifically, the conditional in the loop must combine them.
    m = re.search(
        r"do\s*\{[^}]*wolfSSH_accept[^}]*\}\s*while\s*\([^;]*?"
        r"WS_WANT_READ[^;]*?WS_WANT_WRITE",
        src, re.DOTALL)
    assert m, (
        "Expected wolfSSH_accept retry loop to OR WS_WANT_READ with "
        "WS_WANT_WRITE in its while-condition."
    )


# ---------------------------------------------------------------------------
# A2 -- ssh_read_cb never returns 0 on WANT_READ (would be treated as EOF)
# ---------------------------------------------------------------------------

def test_a2_ssh_read_cb_does_not_return_zero_on_want_read():
    src = _read("main/ssh_server.c")
    # The old bug pattern was `if (n == WS_WANT_READ) return 0;`.  Make sure
    # that exact text is gone.
    assert "WS_WANT_READ) return 0" not in src and \
           "WS_WANT_READ) return  0" not in src, (
        "ssh_read_cb must NOT map WS_WANT_READ to a zero return -- "
        "bridge_pump treats n<=0 as EOF and would tear the session down "
        "on every idle gap."
    )
    # The fix uses a select() wait inside the callback.
    assert "select(" in src, (
        "Expected ssh_read_cb to block via select() on WS_WANT_READ rather "
        "than returning a zero EOF."
    )


# ---------------------------------------------------------------------------
# A3 -- SHA peripheral-clock refcount patch is present
# ---------------------------------------------------------------------------

def test_a3_sha_clock_refcount_patch_present():
    patch_path = os.path.join(
        PROJECT_ROOT,
        "patches/wolfssl__wolfssl/0003-sha-clock-refcount.patch")
    assert os.path.isfile(patch_path), (
        "Expected patches/wolfssl__wolfssl/0003-sha-clock-refcount.patch to "
        "exist -- this restores refcount semantics around the IDF 6 SHA clock "
        "API that periph_module_disable provided in IDF 5.x."
    )
    body = open(patch_path).read()
    assert "_Atomic int" in body, (
        "The 0003 patch must use _Atomic int for the SHA clock refcount."
    )
    assert "esp_tty_sha_clk_set" in body, (
        "The 0003 patch must introduce a refcounted wrapper "
        "esp_tty_sha_clk_set() to replace direct calls to "
        "esp_crypto_sha_enable_periph_clk."
    )


# ---------------------------------------------------------------------------
# A4 -- ESP_ERR_SCEP_PENDING is honoured (long backoff) in smart loop
# ---------------------------------------------------------------------------

def test_a4_scep_pending_honoured_with_long_backoff():
    src = _read("main/wifi.c")
    assert "SCEP_PENDING_RETRY_DELAY_MS" in src, (
        "Expected SCEP_PENDING_RETRY_DELAY_MS to be defined and used in "
        "wifi.c -- a generic ESP_FAIL fallthrough would flood NDES on each "
        "pending request."
    )
    assert "ESP_ERR_SCEP_PENDING" in src, (
        "wifi.c must reference ESP_ERR_SCEP_PENDING to distinguish CA-queued "
        "approval from terminal failure."
    )
    # The smart_on_ip_full path propagates the value rather than swallowing it.
    assert re.search(
        r"enroll_err\s*==\s*ESP_ERR_SCEP_PENDING", src), (
        "smart_on_ip_full must compare scep_enroll's return value against "
        "ESP_ERR_SCEP_PENDING (not just `!= ESP_OK`)."
    )


# ---------------------------------------------------------------------------
# A5 -- TX-power cap applied via helper after every esp_wifi_start()
# ---------------------------------------------------------------------------

def test_a5_apply_max_tx_power_called_at_every_start_site():
    src = _read("main/wifi.c")
    # Count esp_wifi_start() invocations (skip the comment occurrences).
    starts = re.findall(r"esp_wifi_start\s*\(\s*\)", src)
    # 3 actual call sites + the helper comment "esp_wifi_start()" mentions.
    actual_calls = [m for m in re.finditer(
        r"^\s*(?:ESP_ERROR_CHECK\s*\(\s*)?esp_wifi_start\s*\(\s*\)",
        src, re.MULTILINE)]
    assert len(actual_calls) >= 3, (
        f"Expected at least 3 esp_wifi_start() call sites; found {len(actual_calls)}"
    )
    helper_calls = re.findall(r"apply_max_tx_power\s*\(\s*\)\s*;", src)
    # Helper definition + 3 call sites = at least 3 invocations.
    assert len(helper_calls) >= 3, (
        f"apply_max_tx_power() called {len(helper_calls)} time(s); expected "
        ">= 3 (once per esp_wifi_start site)."
    )


# ---------------------------------------------------------------------------
# A6 -- accept log + WiFi reconnect have backoff/rate limiting
# ---------------------------------------------------------------------------

def test_a6_accept_log_rate_limited():
    src = _read("main/ssh_server.c")
    # The "New TCP connection" log must no longer be unconditional.
    # We assert that the log line is surrounded by a counter/check rather
    # than appearing on its own at the top level of the loop.
    m = re.search(r'ESP_LOGI\([^)]*?"New TCP connection[^"]*"', src)
    assert m, "The 'New TCP connection' log line should still exist."
    # Look backwards for a static counter that gates emission.
    snippet = src[max(0, m.start() - 600):m.start()]
    assert "accept_ok_ct" in snippet or "accept_ok_window_start" in snippet, (
        "The 'New TCP connection' INFO log must be rate-limited by a static "
        "counter so a port-scanner cannot flood UART/udp_log."
    )


def test_a6_wifi_reconnect_exponential_backoff():
    src = _read("main/wifi.c")
    # The reconnect block must include a vTaskDelay (the backoff).
    m = re.search(r'backoff %u ms', src)
    assert m, (
        "Expected the WIFI_EVENT_STA_DISCONNECTED reconnect path to log a "
        "backoff value and delay before calling esp_wifi_connect()."
    )
    # And the delay must come from a computed base with jitter.
    assert "jitter" in src, (
        "Expected reconnect backoff to include jitter to avoid synchronised "
        "reconnect storms across a fleet."
    )


# ---------------------------------------------------------------------------
# A7 -- EAP identity is redacted in INFO-level logs
# ---------------------------------------------------------------------------

def test_a7_eap_identity_not_logged_in_cleartext_at_info():
    src = _read("main/wifi.c")
    # The redact helper must be present.
    assert "redact_for_log" in src, (
        "wifi.c must define a redact_for_log helper to keep sensitive "
        "identifiers out of INFO-level log lines."
    )
    # Only flag ESP_LOGI calls that BOTH mention "identity" AND actually
    # interpolate a value (printf-style %s / %.*s).  A bare mention in a
    # message string with no format specifier (e.g. "EAP outer NAI
    # configured") isn't leaking anything and shouldn't trigger the rule.
    fmt_specifier = r'%(?:\.\*)?s'
    info_lines = re.findall(
        r'ESP_LOGI\s*\([^;]*?identity[^;]*?\)\s*;',
        src, re.IGNORECASE | re.DOTALL)
    flagged = [line for line in info_lines if re.search(fmt_specifier, line)]
    assert flagged, (
        "Expected at least one ESP_LOGI line that interpolates an identity "
        "value with %s; the redaction rule needs at least one site to anchor on."
    )
    for line in flagged:
        assert "EAP_IDENTITY" not in line, (
            f"INFO-level log line still prints EAP_IDENTITY directly: {line!r}"
        )
        assert "id_redacted" in line, (
            f"INFO-level identity log line interpolates a value but is not "
            f"using id_redacted: {line!r}"
        )
