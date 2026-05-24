/*
 * zero_wifi_smoke -- minimal WiFi + TCP test for ESP32-S3-Zero on ESP-IDF 6.0.1
 *
 * What it does, in order:
 *   1. Init NVS, esp_netif, esp_event, WiFi driver.
 *   2. esp_wifi_set_country_code("KR", true)  (must allow ch 13).
 *   3. Connect to the PSK SSID "IRIX Setup", get DHCP IP.
 *   4. Open a single outbound TCP socket() / connect() to TEST_HOST:TEST_PORT.
 *   5. Log success or whatever error code came back, then loop printing
 *      "alive" every 5 s.
 *
 * If the chip crashes during step 4 the same way it does in the main
 * firmware (ppRxFragmentProc / ieee80211_output_do NULL deref), we know
 * ESP-IDF 6.0.1 doesn't fix the issue and porting the rest of the project
 * isn't worth it.  If it succeeds, ESP-IDF 6.0.1 is the answer.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#define TAG          "smoke"
#define WIFI_SSID    "IRIX Setup"
#define WIFI_PASS    "motinha@#12234"
#define COUNTRY_CODE "KR"
#define TEST_HOST    "10.57.0.3"   /* python3 -m http.server on Linux box */
#define TEST_PORT    8080

static EventGroupHandle_t s_wifi_eg;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "STA_START -> esp_wifi_connect()");
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *ev = event_data;
        ESP_LOGW(TAG, "STA_DISCONNECTED (reason %d), reconnecting", ev->reason);
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = event_data;
        ESP_LOGI(TAG, "GOT_IP " IPSTR, IP2STR(&ev->ip_info.ip));
        xEventGroupSetBits(s_wifi_eg, WIFI_CONNECTED_BIT);
    }
}

static void tcp_smoke_test(void)
{
    ESP_LOGI(TAG, ">>> opening TCP socket to %s:%d", TEST_HOST, TEST_PORT);

    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        ESP_LOGE(TAG, "socket() failed errno=%d", errno);
        return;
    }
    ESP_LOGI(TAG, "socket() = %d", s);

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port   = htons(TEST_PORT),
    };
    inet_pton(AF_INET, TEST_HOST, &dest.sin_addr);

    ESP_LOGI(TAG, ">>> connect() ...");
    int rc = connect(s, (struct sockaddr *)&dest, sizeof(dest));
    if (rc != 0) {
        ESP_LOGE(TAG, "connect() failed errno=%d (%s)", errno, strerror(errno));
        close(s);
        return;
    }
    ESP_LOGI(TAG, "connect() OK");

    const char *req = "GET / HTTP/1.0\r\nHost: smoke\r\n\r\n";
    int sent = send(s, req, strlen(req), 0);
    ESP_LOGI(TAG, "send() returned %d (errno=%d)", sent, errno);

    char buf[256];
    int rxd = recv(s, buf, sizeof(buf) - 1, 0);
    if (rxd > 0) {
        buf[rxd] = '\0';
        ESP_LOGI(TAG, "recv() %d bytes: first line: %.*s",
                 rxd, (int)(strchr(buf, '\n') ? strchr(buf, '\n') - buf : rxd), buf);
    } else {
        ESP_LOGW(TAG, "recv() returned %d (errno=%d)", rxd, errno);
    }

    close(s);
    ESP_LOGI(TAG, "<<< socket closed cleanly");
}

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32-S3-Zero WiFi smoke test (ESP-IDF " IDF_VER ")");

    /* NVS for WiFi config persistence. */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    s_wifi_eg = xEventGroupCreate();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* Explicit country code so ch12-13 are fully initialised. */
    ESP_ERROR_CHECK(esp_wifi_set_country_code(COUNTRY_CODE, true));
    ESP_LOGI(TAG, "country code set to \"%s\"", COUNTRY_CODE);

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t sta = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .sae_pwe_h2e        = WPA3_SAE_PWE_BOTH,
            .pmf_cfg.capable    = true,
        },
    };
    strncpy((char *)sta.sta.ssid,     WIFI_SSID, sizeof(sta.sta.ssid) - 1);
    strncpy((char *)sta.sta.password, WIFI_PASS, sizeof(sta.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Cap TX power at 14 dBm (56 * 0.25). */
    esp_wifi_set_max_tx_power(56);

    ESP_LOGI(TAG, "waiting for GOT_IP ...");
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_eg, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    if (!(bits & WIFI_CONNECTED_BIT)) {
        ESP_LOGE(TAG, "GOT_IP wait failed; aborting");
        return;
    }

    /* Give the network stack a moment to settle (mirrors what the real
     * firmware does between PSK assoc and the first SCEP HTTP request). */
    vTaskDelay(pdMS_TO_TICKS(2000));

    /* The moment of truth. */
    tcp_smoke_test();

    /* If we reach here, the WiFi RX/TX path didn't crash.  Loop printing
     * an "alive" marker so it's obvious in the capture. */
    int n = 0;
    while (1) {
        ESP_LOGI(TAG, "alive tick=%d", ++n);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
