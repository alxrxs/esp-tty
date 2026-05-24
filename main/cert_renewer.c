/*
 * cert_renewer.c -- live certificate renewal watchdog for esp-tty
 *
 * Background task that polls cred_store_t.not_after, re-enrolls via SCEP
 * when the cert is near expiry, and bounces the EAP-TLS supplicant so the
 * next 802.1X re-auth picks up the new certificate.
 *
 * Assumption: the device is already on the enterprise network when the task
 * runs.  The SCEP server is reachable from the enterprise segment (corporate
 * routing); no PSK detour is performed here.
 *
 * The pure renewal-decision logic is in lib/cert_renewer/cert_renewer_decide.c
 * and is independently unit-tested natively.  Only the task body (FreeRTOS
 * scheduler, esp_eap_client_*, esp_wifi_disconnect) lives here.
 *
 * Only compiled when WIFI_ENTERPRISE_SSID is defined.
 */

#include "config.h"   /* must precede the WIFI_ENTERPRISE_SSID #ifdef */

/* cert_renewer only makes sense for Mode C (runtime SCEP enrollment).
 * Mode B+ (WIFI_USE_ENTERPRISE + WIFI_ENTERPRISE_SSID, embedded certs)
 * doesn't define SCEP_URL and doesn't need renewal at runtime. */
#if defined(WIFI_ENTERPRISE_SSID) && defined(SCEP_URL) && !defined(WIFI_USE_ENTERPRISE)

#include "cert_renewer.h"
#include "cert_renewer_decide.h"

#include <time.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs.h"      /* ESP_ERR_NVS_NOT_FOUND */

#include "esp_heap_caps.h"

#include "cred_store.h"
#include "scep_enroll.h"
#include "wifi.h"     /* smart_eap_apply_creds() */

static const char *TAG = "cert_renew";

/* --------------------------------------------------------------------------
 * Compile-time defaults (override in config.h)
 * -------------------------------------------------------------------------- */

/* Start renewing when fewer than this many days remain. */
#ifndef CERT_RENEWAL_WINDOW_DAYS
# define CERT_RENEWAL_WINDOW_DAYS          7
#endif

/* Sleep interval when no renewal is pending (seconds). */
#ifndef CERT_RENEWAL_CHECK_INTERVAL_SEC
# define CERT_RENEWAL_CHECK_INTERVAL_SEC   86400
#endif

/* Retry interval after a failed renewal attempt (seconds). */
#ifndef CERT_RENEWAL_RETRY_INTERVAL_SEC
# define CERT_RENEWAL_RETRY_INTERVAL_SEC   3600
#endif

/* Guard: track whether the task has already been started. */
static volatile bool s_task_running = false;

/* --------------------------------------------------------------------------
 * Background task body
 * -------------------------------------------------------------------------- */

static void cert_renewer_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "cert renewal watchdog started "
                  "(window=%d days, check=%d s, retry=%d s)",
             CERT_RENEWAL_WINDOW_DAYS,
             CERT_RENEWAL_CHECK_INTERVAL_SEC,
             CERT_RENEWAL_RETRY_INTERVAL_SEC);

    /* cred_store_t is ~14 KB (dev_key[2048] + dev_cert[4096] + ca_chain[8192]
     * + metadata).  The 32 KB task stack also has to accommodate RSA scratch
     * (~4-8 KB) during scep_enroll().  Heap-allocate both stores in internal
     * RAM (same reason as wifi_init_smart -- accessible from any context). */
    cred_store_t *creds_p = heap_caps_calloc(1, sizeof(cred_store_t),
                                              MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    cred_store_t *new_creds_p = heap_caps_calloc(1, sizeof(cred_store_t),
                                                  MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    if (!creds_p || !new_creds_p) {
        ESP_LOGE(TAG, "failed to allocate cred_store_t -- exiting renewal task");
        heap_caps_free(creds_p);
        heap_caps_free(new_creds_p);
        s_task_running = false;
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        /* -- 1. Load current credentials from NVS. */
        memset(creds_p, 0, sizeof(*creds_p));
        esp_err_t load_err = cred_store_load(creds_p);

        if (load_err == ESP_ERR_NVS_NOT_FOUND) {
            /* Device was never enrolled.  This should not happen because
             * wifi_init_smart() enforces enrollment before returning, but
             * be defensive: exit the task rather than spinning. */
            ESP_LOGE(TAG, "no credentials in NVS -- "
                          "device was not enrolled; exiting renewal task");
            goto task_done;
        }

        if (load_err != ESP_OK) {
            ESP_LOGE(TAG, "cred_store_load failed (%s) -- "
                          "retrying in %d s",
                     esp_err_to_name(load_err),
                     CERT_RENEWAL_RETRY_INTERVAL_SEC);
            vTaskDelay(pdMS_TO_TICKS(
                (uint32_t)CERT_RENEWAL_RETRY_INTERVAL_SEC * 1000u));
            continue;
        }

        /* -- 2. Decide whether renewal is needed. */
        time_t now = time(NULL);
        renewal_decision_t decision = cert_renewer_decide(
            now, creds_p->not_after, CERT_RENEWAL_WINDOW_DAYS);

        switch (decision) {
        case RENEWAL_DECISION_SKIP_NO_CLOCK:
            ESP_LOGW(TAG, "clock not yet synced -- "
                          "skipping this cycle; retrying in %d s",
                     CERT_RENEWAL_RETRY_INTERVAL_SEC);
            vTaskDelay(pdMS_TO_TICKS(
                (uint32_t)CERT_RENEWAL_RETRY_INTERVAL_SEC * 1000u));
            continue;

        case RENEWAL_DECISION_SKIP_VALID: {
            int64_t remaining = (int64_t)creds_p->not_after - (int64_t)now;
            ESP_LOGI(TAG, "cert valid, %lld s remaining (%.1f days) -- "
                          "next check in %d s",
                     (long long)remaining,
                     (double)remaining / 86400.0,
                     CERT_RENEWAL_CHECK_INTERVAL_SEC);
            vTaskDelay(pdMS_TO_TICKS(
                (uint32_t)CERT_RENEWAL_CHECK_INTERVAL_SEC * 1000u));
            continue;
        }

        case RENEWAL_DECISION_RENEW_NOW:
            break;  /* fall through to renewal logic */
        }

        /* -- 3. Renewal needed. */
        int64_t remaining = (int64_t)creds_p->not_after - (int64_t)now;
        if (creds_p->not_after == 0) {
            ESP_LOGW(TAG, "not_after=0 sentinel -- cert may be corrupt; "
                          "attempting re-enrollment");
        } else {
            ESP_LOGW(TAG, "cert expires in %lld s (%.1f days) -- "
                          "starting SCEP re-enrollment against %s",
                     (long long)remaining,
                     (double)remaining / 86400.0,
                     SCEP_URL);
        }

        TickType_t t0 = xTaskGetTickCount();
        esp_err_t enroll_err = scep_enroll(SCEP_URL,
                                           SCEP_CHALLENGE_PASSWORD,
                                           NULL);
        TickType_t t1 = xTaskGetTickCount();
        uint32_t elapsed_ms = (uint32_t)((t1 - t0) * portTICK_PERIOD_MS);

        if (enroll_err != ESP_OK) {
            ESP_LOGE(TAG, "SCEP re-enrollment failed (%s) after %u ms -- "
                          "retrying in %d s",
                     esp_err_to_name(enroll_err), (unsigned)elapsed_ms,
                     CERT_RENEWAL_RETRY_INTERVAL_SEC);
            vTaskDelay(pdMS_TO_TICKS(
                (uint32_t)CERT_RENEWAL_RETRY_INTERVAL_SEC * 1000u));
            continue;
        }

        ESP_LOGI(TAG, "SCEP re-enrollment succeeded in %u ms -- "
                      "reloading creds and reconfiguring EAP supplicant",
                 (unsigned)elapsed_ms);

        /* -- 4. Reload freshly written credentials. */
        memset(new_creds_p, 0, sizeof(*new_creds_p));
        esp_err_t reload_err = cred_store_load(new_creds_p);
        if (reload_err != ESP_OK) {
            ESP_LOGE(TAG, "cred_store_load after successful enrollment "
                          "returned %s -- retrying in %d s",
                     esp_err_to_name(reload_err),
                     CERT_RENEWAL_RETRY_INTERVAL_SEC);
            vTaskDelay(pdMS_TO_TICKS(
                (uint32_t)CERT_RENEWAL_RETRY_INTERVAL_SEC * 1000u));
            continue;
        }

        /* -- 5. Push new credentials into the EAP supplicant. */
        esp_err_t apply_err = smart_eap_apply_creds(new_creds_p);
        if (apply_err != ESP_OK) {
            ESP_LOGE(TAG, "smart_eap_apply_creds failed (%s) -- "
                          "retrying in %d s",
                     esp_err_to_name(apply_err),
                     CERT_RENEWAL_RETRY_INTERVAL_SEC);
            vTaskDelay(pdMS_TO_TICKS(
                (uint32_t)CERT_RENEWAL_RETRY_INTERVAL_SEC * 1000u));
            continue;
        }

        /* -- 6. Bounce the connection to trigger 802.1X re-auth.
         *
         * esp_wifi_disconnect() causes WIFI_EVENT_STA_DISCONNECTED, which
         * the persistent wifi_event_handler in wifi.c catches and
         * immediately calls esp_wifi_connect() again.  Because we already
         * updated the EAP supplicant buffers above, the next 802.1X
         * handshake will use the newly enrolled certificate. */
        ESP_LOGI(TAG, "disconnecting to trigger 802.1X re-auth with new cert");
        esp_wifi_disconnect();

        ESP_LOGI(TAG, "renewal complete -- next check in %d s",
                 CERT_RENEWAL_CHECK_INTERVAL_SEC);
        vTaskDelay(pdMS_TO_TICKS(
            (uint32_t)CERT_RENEWAL_CHECK_INTERVAL_SEC * 1000u));
    }

task_done:
    heap_caps_free(creds_p);
    heap_caps_free(new_creds_p);
    s_task_running = false;
    vTaskDelete(NULL);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

esp_err_t cert_renewer_start(void)
{
#ifdef SCEP_NO_NTP_USE_ISSUANCE_TIME
    /* In no-NTP / every-boot-renewal mode the device re-enrolls on every
     * boot via the BOOTSTRAP_FULL path in wifi_init_smart().  There is no
     * need for the background renewal watchdog -- each reboot is itself a
     * renewal.  Return ESP_OK so the caller in app_main() does not log an
     * error. */
    ESP_LOGI(TAG, "cert_renewer: SCEP_NO_NTP_USE_ISSUANCE_TIME active -- "
                  "every-boot renewal handles expiry; background task skipped");
    return ESP_OK;
#else
    if (s_task_running) {
        ESP_LOGW(TAG, "cert_renewer_start() called twice -- ignoring");
        return ESP_FAIL;
    }

    BaseType_t rc = xTaskCreate(
        cert_renewer_task,
        "cert_renew",
        32768,          /* 32 KB stack: scep_enroll needs PKCS#7 + RSA scratch */
        NULL,
        3,              /* low priority; yield to SSH and USB CDC tasks */
        NULL);

    if (rc != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate failed for cert_renew task");
        return ESP_FAIL;
    }

    s_task_running = true;
    ESP_LOGI(TAG, "cert renewal watchdog task created");
    return ESP_OK;
#endif /* SCEP_NO_NTP_USE_ISSUANCE_TIME */
}

#endif /* WIFI_ENTERPRISE_SSID */
