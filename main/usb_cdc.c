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
#include "scrollback.h"
#include "usb_cdc_drain.h"
#include "esp_log.h"

#include <inttypes.h>
#include <stdint.h>

#ifndef BRIDGE_LOOPBACK

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_cdc_acm.h"
#include "tinyusb_default_config.h"

static const char *TAG = "usb_cdc";

static ring_t        *s_usb_to_ssh  = NULL;
static ring_t        *s_ssh_to_usb  = NULL;
static scrollback_t  *s_scrollback  = NULL;

/* ------------------------------------------------------------------ */
/* TinyUSB callbacks                                                   */

/*
 * Adapter that converts tinyusb_cdcacm_read's (int itf, ...) signature into
 * the platform-agnostic usb_cdc_drain_read_fn contract.  The interface index
 * is smuggled through the ctx pointer.
 */
static int tinyusb_read_adapter(void *ctx, uint8_t *buf, size_t cap,
                                size_t *rxd)
{
    int itf = (int)(intptr_t)ctx;
    esp_err_t err = tinyusb_cdcacm_read(itf, buf, cap, rxd);
    return (err == ESP_OK) ? 0 : -1;
}

static void cdc_rx_callback(int itf, cdcacm_event_t *event)
{
    (void)event;

    /* Drain the TinyUSB CDC RX FIFO completely.  The FIFO is
     * CONFIG_TINYUSB_CDC_RX_BUFSIZE (512 B); if we read only one 64 B chunk
     * per callback, larger host writes get stuck in the FIFO and the device
     * NAKs subsequent OUT transfers — blocking host-side writes (agetty,
     * shells, anything writing more than 64 B at once).
     *
     * The drain loop lives in lib/usb_cdc_drain/ so it can be exercised by
     * native unit tests.  The per-chunk overflow log that used to live here
     * has been dropped: the helper reports only the total drained byte count,
     * not per-chunk ring-full information.  Drop visibility is preserved at
     * the source: the host's USB stack will see NAKs / write stalls when the
     * ring is consistently full. */
    (void)usb_cdc_drain(tinyusb_read_adapter,
                        (void *)(intptr_t)itf,
                        s_usb_to_ssh,
                        s_scrollback);
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
        if (n <= 0) {
            /* Ring closed between sessions — wait for it to reopen. */
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, buf, (size_t)n);
        tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, 0);
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */

esp_err_t usb_cdc_init(ring_t *usb_to_ssh, ring_t *ssh_to_usb,
                       scrollback_t *scrollback)
{
    s_usb_to_ssh = usb_to_ssh;
    s_ssh_to_usb = ssh_to_usb;
    s_scrollback = scrollback;

    const tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
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

esp_err_t usb_cdc_init(ring_t *usb_to_ssh, ring_t *ssh_to_usb,
                       scrollback_t *scrollback)
{
    (void)usb_to_ssh; (void)ssh_to_usb; (void)scrollback;
    return ESP_OK;
}

esp_err_t usb_cdc_start_task(void) { return ESP_OK; }

#endif /* BRIDGE_LOOPBACK */
