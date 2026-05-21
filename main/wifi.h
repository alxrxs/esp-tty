/*
 * wifi.h -- Wi-Fi STA init + reconnect for esp-tty
 *
 * Initialises the ESP32-S3 in station mode (WPA2/WPA3-Personal or
 * WPA3-Enterprise via EAP-TLS).
 *
 * Two entry points:
 *
 *   wifi_init_sta()    -- original compile-time-path function.  Behaviour
 *                         is selected by WIFI_USE_ENTERPRISE in config.h.
 *                         Still used by the BRIDGE_LOOPBACK (Wokwi) path.
 *
 *   wifi_init_smart()  -- runtime state machine that decides at boot-time
 *                         whether to use the bootstrap (PSK) or enterprise
 *                         (EAP-TLS) network, and whether to (re-)enroll via
 *                         SCEP.  Available only when WIFI_ENTERPRISE_SSID is
 *                         defined in config.h.  Falls through to the
 *                         wifi_init_sta() code path otherwise (in main.c).
 */

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Call once from app_main() after nvs_flash_init().
 * Returns ESP_OK when an IP address has been obtained.
 * Returns ESP_FAIL if WIFI_MAX_RETRY attempts were exhausted. */
esp_err_t wifi_init_sta(void);

/* Two-network boot-time state machine (Mode C).
 *
 * Opt-in: only available when WIFI_ENTERPRISE_SSID is defined in config.h
 * WITHOUT WIFI_USE_ENTERPRISE.  Reads the NVS credential store, decides
 * whether bootstrap or enterprise mode is appropriate, optionally syncs NTP
 * and/or runs SCEP enrollment, and blocks until the enterprise network has an
 * IP or all paths are exhausted.
 *
 * On successful SCEP enrollment the function calls esp_restart() rather than
 * returning (fresh state avoids credential-reload complexity).
 *
 * Returns:
 *   ESP_OK   -- enterprise network connected with an IP.
 *   ESP_FAIL -- all paths exhausted; caller may proceed without Wi-Fi. */
#if defined(WIFI_ENTERPRISE_SSID) && !defined(WIFI_USE_ENTERPRISE)
esp_err_t wifi_init_smart(void);
#endif

/* PSK bootstrap + EAP-TLS state machine for Mode B with bootstrap (Mode B+).
 *
 * Opt-in: available when BOTH WIFI_USE_ENTERPRISE and WIFI_ENTERPRISE_SSID are
 * defined.  Like Mode C, but uses build-embedded certs instead of SCEP/NVS.
 * WIFI_SSID/WIFI_PASS is the PSK bootstrap network; WIFI_ENTERPRISE_SSID is
 * the EAP-TLS target.  If NTP_BEFORE_EAPTLS (default on when NTP_ENABLE is
 * defined) and clock is unsynced, syncs time on the bootstrap network first.
 *
 * Returns:
 *   ESP_OK   -- enterprise network connected with an IP.
 *   ESP_FAIL -- all paths exhausted; caller may proceed without Wi-Fi. */
#if defined(WIFI_ENTERPRISE_SSID) && defined(WIFI_USE_ENTERPRISE)
esp_err_t wifi_init_enterprise_bootstrap(void);
#endif

/* smart_eap_apply_creds -- update the EAP supplicant with new credentials.
 *
 * Called by cert_renewer.c after a successful SCEP re-enrollment.  Feeds the
 * new CA cert, client cert, and private key into the EAP supplicant without
 * tearing down the network stack.  The caller should follow up with
 * esp_wifi_disconnect() to trigger 802.1X re-auth with the new cert.
 *
 * Returns ESP_OK on success, ESP_FAIL if any credential buffer is empty or
 * if an ESP-IDF EAP API call fails.
 *
 * Only available when WIFI_ENTERPRISE_SSID is defined WITHOUT WIFI_USE_ENTERPRISE
 * (Mode C); Mode B+ uses embedded certs and has no cert renewer. */
#if defined(WIFI_ENTERPRISE_SSID) && !defined(WIFI_USE_ENTERPRISE)
#include "cred_store.h"
esp_err_t smart_eap_apply_creds(const cred_store_t *creds);
#endif

#ifdef __cplusplus
}
#endif
