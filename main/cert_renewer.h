/*
 * cert_renewer.h -- live certificate renewal watchdog for esp-tty
 *
 * Launches a background FreeRTOS task that polls the stored client cert's
 * NotAfter epoch and re-enrolls via SCEP when the cert is within
 * CERT_RENEWAL_WINDOW_DAYS of expiry.
 *
 * Assumptions:
 *   - The device is already connected to the enterprise (EAP-TLS) network
 *     when cert_renewer_start() is called.  The SCEP server is reachable
 *     from the enterprise segment via corporate routing -- no PSK detour is
 *     needed for renewal.
 *   - wifi_init_smart() has returned ESP_OK (i.e. NVS is initialised and
 *     credentials exist).
 *
 * After a successful renewal the task calls smart_eap_apply_creds() (wifi.h)
 * to push the new credentials into the EAP supplicant, then calls
 * esp_wifi_disconnect() to force 802.1X re-auth with the new certificate.
 *
 * On any enrollment failure the task sleeps CERT_RENEWAL_RETRY_INTERVAL_SEC
 * and retries indefinitely -- it never gives up.
 *
 * Available only when WIFI_ENTERPRISE_SSID is defined.
 *
 * The pure renewal-decision helper lives in lib/cert_renewer/ and is
 * native-testable.  This header re-exports it for convenience.
 */

#pragma once

#ifdef WIFI_ENTERPRISE_SSID

#include "esp_err.h"

/* Re-export the pure decision helper from lib/cert_renewer/ so callers
 * only need to include this one header. */
#include "cert_renewer_decide.h"

/*
 * cert_renewer_start -- launch the background renewal task.
 *
 * Call once after wifi_init_smart() returns ESP_OK.  Calling it a second
 * time returns ESP_FAIL (task already running) without creating a second
 * task.
 *
 * Returns:
 *   ESP_OK   -- task created successfully.
 *   ESP_FAIL -- xTaskCreate() failed, or already called.
 */
esp_err_t cert_renewer_start(void);

#endif /* WIFI_ENTERPRISE_SSID */
