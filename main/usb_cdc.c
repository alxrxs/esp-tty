/*
 * usb_cdc.c -- TinyUSB CDC ACM driver
 *
 * RX path: TinyUSB callback -> ring_send(usb_to_ssh)
 * TX path: FreeRTOS task pulls from ssh_to_usb ring -> CDC TX
 *
 * When BRIDGE_LOOPBACK is defined (Wokwi simulation) TinyUSB is absent;
 * the whole file becomes no-ops since the bridge never calls usb_cdc_*.
 *
 * When USB_DEBUG_CONSOLE_ONLY is defined the USB-OTG peripheral is not
 * initialised so that the USB-Serial-JTAG controller can claim the shared
 * GPIO19/20 pins instead.  All public functions become no-ops in that case.
 */

#include "usb_cdc.h"
#include "scrollback.h"
#include "usb_cdc_drain.h"
#include "config.h"            /* USB_MANUFACTURER_STRING etc. */
#include "esp_log.h"

#include <inttypes.h>
#include <stdint.h>

#if !defined(BRIDGE_LOOPBACK) && !defined(USB_DEBUG_CONSOLE_ONLY)

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_cdc_acm.h"
#include "tinyusb_default_config.h"

static const char *TAG = "usb_cdc";

/* Custom USB device descriptor. Overrides sdkconfig at runtime via
 * tinyusb_config_t.descriptor.device. Class/SubClass/Protocol = EF/02/01
 * mark this as a USB composite device using Interface Association Descriptors
 * (IAD), which is what TinyUSB's default CDC descriptor expects. */
static const tusb_desc_device_t s_device_descriptor = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,                 /* USB 2.0 */
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE, /* 64 */
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = USB_DEVICE_VERSION,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01,
};

/* Custom USB string descriptors. Overrides sdkconfig's CONFIG_TINYUSB_DESC_*_STRING
 * at runtime via tinyusb_config_t.descriptor.string.
 *
 * Index 0 is the 2-byte language identifier (0x0409 = US English) encoded as
 * a string. Indices 1-4 are referenced by the device descriptor's
 * iManufacturer/iProduct/iSerialNumber and the CDC interface's iInterface. */
static const char *const s_usb_strings[] = {
    (const char[]){0x09, 0x04},   /* 0: LANGID = 0x0409 (US English) */
    USB_MANUFACTURER_STRING,       /* 1: iManufacturer */
    USB_PRODUCT_STRING,            /* 2: iProduct */
    USB_SERIAL_STRING,             /* 3: iSerialNumber */
    USB_CDC_STRING,                /* 4: CDC interface name */
};

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
     * NAKs subsequent OUT transfers -- blocking host-side writes (agetty,
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
/* TX pump task: ssh_to_usb ring -> CDC TX                             */

static void usb_tx_task(void *arg)
{
    uint8_t buf[256];

    while (1) {
        int n = ring_recv(s_ssh_to_usb, buf, sizeof(buf));
        if (n <= 0) {
            /* Ring closed between sessions -- wait for it to reopen. */
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

    tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
    tusb_cfg.descriptor.device       = &s_device_descriptor;
    /* TinyUSB's field type is `const char **`; our array is `const char *const []`.
     * The cast acknowledges TinyUSB's looser const-annotation without dropping
     * the inner constness on our side. */
    tusb_cfg.descriptor.string       = (const char **)s_usb_strings;
    tusb_cfg.descriptor.string_count = sizeof(s_usb_strings) / sizeof(s_usb_strings[0]);
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

#else /* BRIDGE_LOOPBACK or USB_DEBUG_CONSOLE_ONLY -- stubs, never called */

esp_err_t usb_cdc_init(ring_t *usb_to_ssh, ring_t *ssh_to_usb,
                       scrollback_t *scrollback)
{
    (void)usb_to_ssh; (void)ssh_to_usb; (void)scrollback;
    return ESP_OK;
}

esp_err_t usb_cdc_start_task(void) { return ESP_OK; }

#endif /* BRIDGE_LOOPBACK || USB_DEBUG_CONSOLE_ONLY */
