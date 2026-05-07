/*
 * wifi.h — Wi-Fi STA init + reconnect for esp-tty
 *
 * Initialises the ESP32-S3 in station mode (WPA2/WPA3-Personal).
 * Blocks until the first IP address is obtained or permanent failure
 * is declared.  After that, reconnection on drops is handled
 * transparently by the internal event handler.
 *
 * Extension point for WPA2-Enterprise (EAP-TLS):
 *   Search for "EAP-TLS EXTENSION POINT" in wifi.c.
 *   Populate wifi_eap_config_t and call esp_wifi_sta_enterprise_enable()
 *   before esp_wifi_start() — no other changes required.
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

#ifdef __cplusplus
}
#endif
