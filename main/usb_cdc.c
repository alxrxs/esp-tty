/*
 * usb_cdc.c — TinyUSB CDC ACM driver
 *
 * RX path: TinyUSB callback → ring_send(usb_to_ssh)
 * TX path: FreeRTOS task pulls from ssh_to_usb ring → CDC TX
 *
 * When BRIDGE_LOOPBACK is defined (Wokwi simulation) TinyUSB is absent;
 * the whole file becomes no-ops since the bridge never calls usb_cdc_*.
 */

#include "usb_cdc.h"
#include "esp_log.h"

#include <inttypes.h>

#ifndef BRIDGE_LOOPBACK

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_cdc_acm.h"

static const char *TAG = "usb_cdc";

static ring_t *s_usb_to_ssh = NULL;
static ring_t *s_ssh_to_usb = NULL;

/* ------------------------------------------------------------------ */
/* TinyUSB callbacks                                                   */

static void cdc_rx_callback(int itf, cdcacm_event_t *event)
{
    (void)event;
    uint8_t buf[64];
    size_t  rxd = 0;

    esp_err_t err = tinyusb_cdcacm_read(itf, buf, sizeof(buf), &rxd);
    if (err != ESP_OK || rxd == 0) return;

    /* Use the non-blocking variant — ring_send() can block up to 50 ms per
     * chunk, which risks stalling USB enumeration when called from a TinyUSB
     * callback (interrupt-adjacent context).  ring_try_send() returns
     * immediately; on overflow we drop the data and log a warning once per
     * N dropped bursts (rate-limited to avoid flooding). */
    int written = ring_try_send(s_usb_to_ssh, buf, rxd);
    if (written >= 0 && (size_t)written < rxd) {
        static uint32_t s_drop_count = 0;
        s_drop_count++;
        if ((s_drop_count & 0xFF) == 1) {   /* log every 256 drops */
            ESP_LOGW(TAG, "CDC RX overflow: dropped %zu bytes (total drops: %" PRIu32 ")",
                     rxd - (size_t)written, s_drop_count);
        }
    }
}

static void cdc_line_state_callback(int itf, cdcacm_event_t *event)
{
    int dtr = event->line_state_changed_data.dtr;
    int rts = event->line_state_changed_data.rts;
    ESP_LOGI(TAG, "CDC ch%d: DTR=%d RTS=%d", itf, dtr, rts);
}

/* ------------------------------------------------------------------ */
/* TX pump task: ssh_to_usb ring → CDC TX                             */

static void usb_tx_task(void *arg)
{
    uint8_t buf[256];

    while (1) {
        int n = ring_recv(s_ssh_to_usb, buf, sizeof(buf));
        if (n <= 0) break;

        tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, buf, (size_t)n);
        tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, 0);
    }

    ESP_LOGW(TAG, "TX task exiting (ring closed)");
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */

esp_err_t usb_cdc_init(ring_t *usb_to_ssh, ring_t *ssh_to_usb)
{
    s_usb_to_ssh = usb_to_ssh;
    s_ssh_to_usb = ssh_to_usb;

    const tinyusb_config_t tusb_cfg = {0};
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    const tinyusb_config_cdcacm_t acm_cfg = {
        .cdc_port                    = TINYUSB_CDC_ACM_0,
        .callback_rx                 = cdc_rx_callback,
        .callback_rx_wanted_char     = NULL,
        .callback_line_state_changed = cdc_line_state_callback,
        .callback_line_coding_changed = NULL,
    };
    ESP_ERROR_CHECK(tinyusb_cdcacm_init(&acm_cfg));

    ESP_LOGI(TAG, "TinyUSB CDC ACM initialised");
    return ESP_OK;
}

esp_err_t usb_cdc_start_task(void)
{
    BaseType_t rc = xTaskCreate(usb_tx_task, "usb_tx",
                                4096, NULL, 5, NULL);
    if (rc != pdPASS) {
        ESP_LOGE(TAG, "Failed to create USB TX task");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

#else /* BRIDGE_LOOPBACK — stubs, never called */

esp_err_t usb_cdc_init(ring_t *usb_to_ssh, ring_t *ssh_to_usb)
{
    (void)usb_to_ssh; (void)ssh_to_usb;
    return ESP_OK;
}

esp_err_t usb_cdc_start_task(void) { return ESP_OK; }

#endif /* BRIDGE_LOOPBACK */
