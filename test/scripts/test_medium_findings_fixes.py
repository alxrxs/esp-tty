"""Structural pytest assertions for round-2 MEDIUM-severity audit fixes.

Each test grep-asserts on a specific code change so that future refactors
don't silently regress the fix.  Pair with the relevant native unit tests
where the matcher logic can be exercised on the host.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# ---- M1 boot ordering ----------------------------------------------------

def test_m1_ssh_server_starts_before_cert_renewer_in_main():
    src = _read("main/main.c")
    ssh_idx = src.find("ssh_server_start(usb_to_ssh")
    crt_idx = src.find("cert_renewer_start()")
    assert ssh_idx > 0 and crt_idx > 0
    assert ssh_idx < crt_idx, (
        "main.c must call ssh_server_start() before cert_renewer_start() "
        "so the host-key generation gets a head start over scep_enroll's "
        "RSA scratch.  See M1.")


# ---- M2 rollback liveness gate ------------------------------------------

def test_m2_rollback_timer_checks_ssh_listening():
    src = _read("main/main.c")
    assert "ssh_server_is_listening()" in src, (
        "rollback_timer_cb must check ssh_server_is_listening() before "
        "calling esp_ota_mark_app_valid_cancel_rollback.  See M2.")
    # The check must precede the mark_valid call in the function body.
    cb_start = src.find("rollback_timer_cb")
    mark_idx = src.find("esp_ota_mark_app_valid_cancel_rollback",
                        cb_start if cb_start > 0 else 0)
    chk_idx = src.find("ssh_server_is_listening",
                       cb_start if cb_start > 0 else 0)
    assert chk_idx > 0 and mark_idx > 0 and chk_idx < mark_idx


def test_m2_ssh_server_header_exposes_is_listening():
    h = _read("main/ssh_server.h")
    assert "bool ssh_server_is_listening(void)" in h
    c = _read("main/ssh_server.c")
    assert "s_ssh_listening = true" in c, (
        "ssh_server_task must set s_ssh_listening = true after bind+listen.")


# ---- M3 wifi double-init guard ------------------------------------------

def test_m3_wifi_double_init_guard():
    src = _read("main/wifi.c")
    assert "s_wifi_inited" in src
    assert "atomic_exchange(&s_wifi_inited" in src, (
        "wifi.c must guard esp_netif_init/esp_event_loop_create_default/"
        "esp_wifi_init against double calls via an atomic flag.  See M3.")
    # Ensures we tear down a stale event-group handle before re-creating it.
    assert "wifi_event_group_reset" in src


# ---- M4 terminal resize callback race -----------------------------------

def test_m4_terminal_resize_callback_under_session_mutex():
    src = _read("main/ssh_server.c")
    # The SetCb/SetCtx pair must appear after wolfSSH_set_fd (also under
    # the mutex region opened just before wolfSSH_new), and before the
    # xSemaphoreGive that releases that region.
    setcb_idx = src.find("wolfSSH_SetTerminalResizeCb(ssh, term_resize_cb);")
    setfd_idx = src.find("wolfSSH_set_fd(ssh, client_fd);")
    active_ssh_idx = src.find("s_active_ssh = ssh;")
    assert setfd_idx > 0 and setcb_idx > 0 and active_ssh_idx > 0
    # The Set* must sit between set_fd and the s_active_ssh assignment,
    # i.e. comfortably inside the held-mutex region (mutex is released a
    # few lines after the s_active_ssh = ssh line).
    assert setfd_idx < setcb_idx < active_ssh_idx, (
        "Terminal-resize callback must be registered immediately after "
        "wolfSSH_set_fd, still inside the s_session_mutex window.  See M4.")


# ---- M5 wolfSSL NO_TLS ---------------------------------------------------

def test_m5_wolfssl_no_tls_defined():
    src = _read("components/wolfssl/include/user_settings.h")
    assert "#define NO_TLS" in src, (
        "user_settings.h must define NO_TLS so the TLS record layer is "
        "stripped from wolfSSL (wolfSSH does not use it).  See M5.")


# ---- M6 success-auth logs -----------------------------------------------

def test_m6_successful_auth_is_logged():
    src = _read("main/ssh_server.c")
    # There should be at least two ESP_LOGI lines reading "Auth accepted"
    # (one for OTA, one for TTY).
    assert src.count('"Auth accepted:') >= 2, (
        "Accepted SSH pubkey authentications must be logged with their "
        "(sanitized) username.  See M6.")


# ---- M7 security-failure backoff ----------------------------------------

def test_m7_auth_disconnect_uses_longer_backoff():
    src = _read("main/wifi.c")
    # The reason classification must reference at least these symbols.
    for sym in (
        "WIFI_REASON_AUTH_FAIL",
        "WIFI_REASON_HANDSHAKE_TIMEOUT",
        "WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT",
        "WIFI_REASON_ASSOC_FAIL",
    ):
        assert sym in src, f"Missing classification of {sym} in wifi.c"
    # And the cap must be raised for security failures.
    assert "security_fail" in src
    assert "300000u" in src, (
        "Security-relevant disconnects must use a 5+ minute backoff cap.")


# ---- M8 embedded cert expiry parsing ------------------------------------

def test_m8_embedded_client_cert_expiry_is_evaluated():
    src = _read("main/wifi.c")
    assert "eval_embedded_client_cert_expired" in src, (
        "wifi_init_enterprise_bootstrap must call a helper that parses "
        "the embedded client.crt and returns its expiry status.  See M8.")
    assert "mbedtls_x509_crt_parse" in src


# ---- M9 usb_cdc_drain overflow ------------------------------------------

def test_m9_usb_cdc_drain_uses_size_t_internally():
    src = _read("lib/usb_cdc_drain/usb_cdc_drain.c")
    # total must be declared as size_t, and the function must clamp to
    # INT_MAX on the return path.
    assert "size_t total" in src
    assert "INT_MAX" in src, (
        "usb_cdc_drain must clamp its size_t accumulator to INT_MAX "
        "before returning it as int.  See M9.")


# ---- M10 scep_transport body_len bound ----------------------------------

def test_m10_scep_transport_rejects_oversize_body():
    src = _read("lib/scep_transport/scep_transport.c")
    assert "body_len > (size_t)INT_MAX" in src, (
        "scep_transport must reject body_len > INT_MAX before casting to "
        "int for esp_http_client_set_post_field.  See M10.")


# ---- M11 scrollback used+len overflow -----------------------------------

def test_m11_scrollback_used_plus_len_overflow_guard():
    src = _read("lib/scrollback/scrollback.c")
    # The reversed-bound form must appear at least twice (two impls).
    matches = src.count("len < sb->cap - sb->used")
    assert matches >= 2, (
        "scrollback used+len addition must be rewritten as "
        "`len < cap - used` to avoid size_t wrap.  See M11.")


# ---- M12 pkcs7_padded_len overflow --------------------------------------

def test_m12_pkcs7_padded_len_overflow_guard():
    src = _read("lib/scep_proto/scep_proto.c")
    assert "n > SIZE_MAX - 16" in src, (
        "pkcs7_padded_len must return 0 (error) when input n is within "
        "16 bytes of SIZE_MAX.  See M12.")
    # And callers must check for the 0 sentinel.
    assert "padded_len == 0" in src


# ---- M13 EAP anonymous identity hook ------------------------------------

def test_m13_eap_anonymous_identity_supported():
    src = _read("main/wifi.c")
    assert "EAP_ANONYMOUS_IDENTITY" in src
    assert "esp_eap_client_set_anonymous_identity" in src, (
        "wifi.c must call esp_eap_client_set_anonymous_identity when "
        "EAP_ANONYMOUS_IDENTITY is defined.  See M13.")
    # And the example config must document the option.
    ex = _read("main/config.example.h")
    assert "EAP_ANONYMOUS_IDENTITY" in ex


# ---- M14 udp_log tag denylist -------------------------------------------

def test_m14_udp_log_tag_denylist():
    src = _read("lib/udp_log/udp_log.c")
    assert "UDP_LOG_TAG_DENYLIST" in src
    assert "udp_log_tag_blocked" in src, (
        "udp_log must apply a tag denylist before forwarding lines over "
        "the network.  See M14.")
    # The default denylist must cover at least the sensitive tags listed
    # in the audit (scep_enroll / cert_renew / wifi / ssh_server).
    for tag in ("scep_enroll", "cert_renew", "wifi", "ssh_server"):
        assert f'"{tag}"' in src, (
            f'Default UDP_LOG_TAG_DENYLIST must include "{tag}"')


# ---- M15 TLS validation clock floor in no-NTP mode ----------------------

def test_m15_scep_no_ntp_sets_clock_floor():
    src = _read("main/wifi.c")
    assert "SCEP_NO_NTP_BUILD_EPOCH" in src, (
        "When SCEP_NO_NTP_USE_ISSUANCE_TIME is defined, wifi.c must apply "
        "a settimeofday() floor before HTTPS to the SCEP server so "
        "mbedTLS time validation isn't running at epoch 0.  See M15.")
    # And the call must actually use settimeofday with that floor.
    assert "settimeofday" in src
