/*
 * wifi.c — Wi-Fi STA init + automatic reconnect for esp-tty
 *
 * Implements WPA2/WPA3-Personal station mode with:
 *   - Full event-driven connect flow via esp_event
 *   - Automatic reconnect on WIFI_EVENT_STA_DISCONNECTED
 *   - EventGroup signalling when IP is obtained (WIFI_CONNECTED_BIT)
 *   - IP address printed to UART log in the IP_EVENT_STA_GOT_IP handler
 *   - Clearly marked extension point for WPA2-Enterprise / EAP-TLS
 *
 * Compile-time credentials come from main/config.h (gitignored).
 * Copy config.h.example → config.h and fill in WIFI_SSID / WIFI_PASS.
 */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "wifi.h"
#ifdef BRIDGE_LOOPBACK
/* QEMU/Wokwi simulation: open AP, no password, no authmode requirement */
#define WIFI_SSID  "Wokwi-GUEST"
#define WIFI_PASS  ""
#define WIFI_AUTH_THRESHOLD  WIFI_AUTH_OPEN
#define WIFI_SAE_MODE        WPA3_SAE_PWE_UNSPECIFIED
#else
#include "config.h"   /* WIFI_SSID, WIFI_PASS */
#endif

/* --------------------------------------------------------------------------
 * Build-time knobs
 * -------------------------------------------------------------------------- */

/* Maximum consecutive reconnect attempts before wifi_init_sta() returns
 * ESP_FAIL.  After that the event handler still keeps trying indefinitely
 * (see RECONNECT_FOREVER below), so the rest of the firmware can decide
 * what to do (e.g. keep the SSH task alive for a pre-connected session). */
#ifndef WIFI_MAX_RETRY
#define WIFI_MAX_RETRY  10
#endif

/* WPA3-SAE mode.  WPA3_SAE_PWE_BOTH tries Hash-to-Element first and falls
 * back to Hunt-and-Peck — safe for mixed WPA2/WPA3 APs. */
#ifndef WIFI_SAE_MODE
#define WIFI_SAE_MODE   WPA3_SAE_PWE_BOTH
#endif

/* Minimum auth mode accepted during scan.  WIFI_AUTH_WPA2_PSK rejects
 * open / WEP / WPA1 APs.  Raise to WIFI_AUTH_WPA3_PSK for WPA3-only. */
#ifndef WIFI_AUTH_THRESHOLD
#define WIFI_AUTH_THRESHOLD  WIFI_AUTH_WPA2_PSK
#endif

/* --------------------------------------------------------------------------
 * EventGroup bit definitions
 * -------------------------------------------------------------------------- */
#define WIFI_CONNECTED_BIT  BIT0   /* IP obtained              */
#define WIFI_FAIL_BIT       BIT1   /* max retries exhausted    */

/* --------------------------------------------------------------------------
 * Module-private state
 * -------------------------------------------------------------------------- */
static const char *TAG = "wifi";

static EventGroupHandle_t s_wifi_event_group;
static int                s_retry_num = 0;

/* Kept so the enterprise extension point can call esp_netif_get_ip_info()
 * from a task if needed. */
static esp_netif_t *s_sta_netif = NULL;

/* --------------------------------------------------------------------------
 * Event handler
 *
 * Runs in the system event task context (stack ~3 kB).  Keep it lean.
 * -------------------------------------------------------------------------- */
static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t          event_id,
                               void            *event_data)
{
    if (event_base == WIFI_EVENT) {

        if (event_id == WIFI_EVENT_STA_START) {
            /* Driver is up — kick off the first connection attempt. */
            ESP_LOGI(TAG, "STA started, connecting to \"%s\" …", WIFI_SSID);
            esp_wifi_connect();

        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            wifi_event_sta_disconnected_t *ev =
                (wifi_event_sta_disconnected_t *)event_data;

            /* Clear the connected bit so callers that poll it see the drop. */
            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

            if (s_retry_num < WIFI_MAX_RETRY) {
                s_retry_num++;
                ESP_LOGW(TAG, "disconnected (reason %d), retry %d/%d",
                         ev->reason, s_retry_num, WIFI_MAX_RETRY);
                esp_wifi_connect();
            } else {
                /* Signal permanent failure to wifi_init_sta()'s wait. */
                xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
                ESP_LOGE(TAG, "gave up after %d retries (reason %d)",
                         WIFI_MAX_RETRY, ev->reason);

                /* RECONNECT_FOREVER: keep retrying even after signalling
                 * failure so we recover if the AP comes back later.
                 * Remove the call below if you want hard-stop semantics. */
                esp_wifi_connect();
            }
        }

    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)event_data;

        /* ----------------------------------------------------------------
         * Print the assigned IP to the UART log — the primary discovery
         * mechanism for v1 (no mDNS).  The SSH task can start now.
         * ---------------------------------------------------------------- */
        ESP_LOGI(TAG, "IP address : " IPSTR, IP2STR(&ev->ip_info.ip));
        ESP_LOGI(TAG, "Netmask    : " IPSTR, IP2STR(&ev->ip_info.netmask));
        ESP_LOGI(TAG, "Gateway    : " IPSTR, IP2STR(&ev->ip_info.gw));

        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

esp_err_t wifi_init_sta(void)
{
#ifdef BRIDGE_LOOPBACK
    /* QEMU/Wokwi: no WiFi radio — init the TCP/IP stack only so LwIP
     * sockets work, then return immediately (SSH server binds to 0.0.0.0). */
    ESP_LOGI(TAG, "BRIDGE_LOOPBACK: skipping WiFi, init netif only");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();
    return ESP_OK;
#endif

    /* 1. Create the EventGroup used to synchronise with app_main / ssh_task. */
    s_wifi_event_group = xEventGroupCreate();
    configASSERT(s_wifi_event_group);

    /* 2. Initialise the TCP/IP stack and create the default event loop.
     *    Order matters: esp_netif_init() before esp_event_loop_create_default()
     *    before esp_netif_create_default_wifi_sta(). */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_sta_netif = esp_netif_create_default_wifi_sta();
    configASSERT(s_sta_netif);

    /* 3. Initialise the Wi-Fi driver with the default (ROM-based) config. */
    wifi_init_config_t driver_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&driver_cfg));

    /* 4. Register event handlers.
     *    instance_any_id  → all WIFI_EVENT sub-events (start, disconnect, …)
     *    instance_got_ip  → IP_EVENT_STA_GOT_IP only */
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID,
        &wifi_event_handler, NULL, &instance_any_id));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP,
        &wifi_event_handler, NULL, &instance_got_ip));

    /* 5. Build the STA config.
     *
     *    WPA2/WPA3-Personal (PSK) fields:
     *      .ssid              — target network name
     *      .password          — PSK (8–63 chars for WPA2; same for WPA3)
     *      .threshold.authmode— lowest auth mode accepted during scan
     *      .sae_pwe_h2e       — SAE method: BOTH = try H2E, fall back to H&P
     *      .pmf_cfg.capable   — advertise PMF (required for WPA3)
     *      .pmf_cfg.required  — enforce PMF (set true for WPA3-only networks)
     *
     * -----------------------------------------------------------------------
     * EAP-TLS EXTENSION POINT (WPA2/WPA3-Enterprise — eduroam, UPB, etc.)
     * -----------------------------------------------------------------------
     * To switch to EAP-TLS:
     *   a) Remove .password and .threshold.authmode from the config below.
     *   b) Set .pmf_cfg.required = true for WPA3-Enterprise.
     *   c) After esp_wifi_set_config(), add:
     *
     *      #include "esp_eap_client.h"
     *
     *      // Phase-1 identity (outer, anonymous for privacy):
     *      ESP_ERROR_CHECK(esp_eap_client_set_identity(
     *          (uint8_t *)EAP_IDENTITY, strlen(EAP_IDENTITY)));
     *
     *      // CA certificate (DER or PEM, loaded via EMBED_FILES or NVS):
     *      ESP_ERROR_CHECK(esp_eap_client_set_ca_cert(
     *          ca_pem_start, ca_pem_end - ca_pem_start));
     *
     *      // Client certificate + private key (EAP-TLS only):
     *      ESP_ERROR_CHECK(esp_eap_client_set_certificate_and_key(
     *          client_crt_start, client_crt_end - client_crt_start,
     *          client_key_start, client_key_end - client_key_start,
     *          NULL, 0));   // NULL key_password if key is unencrypted
     *
     *      // For EAP-PEAP / EAP-TTLS instead of TLS:
     *      //   esp_eap_client_set_username(...)
     *      //   esp_eap_client_set_password(...)
     *
     *      ESP_ERROR_CHECK(esp_wifi_sta_enterprise_enable());
     *
     *   d) Remove esp_wifi_sta_enterprise_enable() guard; the rest of this
     *      function (esp_wifi_start, xEventGroupWaitBits, …) is unchanged.
     * -----------------------------------------------------------------------
     */
    wifi_config_t wifi_config = {
        .sta = {
            /* Credentials from config.h (gitignored). */
            .ssid     = WIFI_SSID,
            .password = WIFI_PASS,

            /* Reject APs weaker than WPA2-PSK.
             * Bump to WIFI_AUTH_WPA3_PSK for WPA3-only environments. */
            .threshold.authmode = WIFI_AUTH_THRESHOLD,

            /* SAE (WPA3) mode: try Hash-to-Element, fall back to
             * Hunt-and-Peck.  Safe for mixed WPA2/WPA3 routers. */
            .sae_pwe_h2e = WIFI_SAE_MODE,

            /* PMF: advertise support (required for WPA3 association),
             * but not mandatory so WPA2-only APs still work. */
            .pmf_cfg = {
                .capable  = true,
                .required = false,
            },
        },
    };

    /* 6. Apply mode, config, then start the driver.
     *    WIFI_EVENT_STA_START fires after esp_wifi_start() returns, which
     *    triggers esp_wifi_connect() in the event handler above. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta complete, waiting for IP …");

    /* 7. Block until connected+IP or retry-limit exhausted.
     *    BRIDGE_LOOPBACK uses a 10 s timeout so QEMU/CI doesn't hang forever
     *    waiting for a WiFi radio that doesn't exist. */
#ifdef BRIDGE_LOOPBACK
#define WIFI_WAIT_TICKS  pdMS_TO_TICKS(10000)
#else
#define WIFI_WAIT_TICKS  portMAX_DELAY
#endif
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,   /* do not clear on exit */
        pdFALSE,   /* wait for either bit  */
        WIFI_WAIT_TICKS);

    /* 8. Deregister the one-shot instances; the handler stays registered
     *    for reconnect events from the persistent WIFI_EVENT registration. */
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to \"%s\"", WIFI_SSID);
        return ESP_OK;
    }

    if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "failed to connect to \"%s\"", WIFI_SSID);
        return ESP_FAIL;
    }

    /* Should never reach here (portMAX_DELAY wait). */
    ESP_LOGE(TAG, "unexpected event group state 0x%lx", (unsigned long)bits);
    return ESP_FAIL;
}
