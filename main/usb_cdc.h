/*
 * usb_cdc.h — TinyUSB CDC ACM device driver for esp-tty
 *
 * Exposes the ESP32-S3 native USB port as /dev/ttyACM0 on the Linux host.
 * Data flows through two shared ring buffers owned by the caller:
 *
 *   CDC RX → usb_to_ssh   (Linux host → ESP32 → SSH client)
 *   ssh_to_usb → CDC TX   (SSH client → ESP32 → Linux host)
 *
 * Call usb_cdc_init() once, then usb_cdc_start_task() to launch the TX
 * pump task.  RX is interrupt-driven via a TinyUSB callback.
 */

#pragma once

#include "esp_err.h"
#include "ring.h"
#include "scrollback.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialise TinyUSB CDC ACM.  Must be called before any FreeRTOS tasks
 * that use the ring buffers are created.
 *
 * usb_to_ssh: ring that receives bytes from the Linux host (CDC RX → ring)
 * ssh_to_usb: ring that drains bytes to   the Linux host (ring → CDC TX)
 */
esp_err_t usb_cdc_init(ring_t *usb_to_ssh, ring_t *ssh_to_usb,
                       scrollback_t *scrollback);

/*
 * Start the CDC TX pump FreeRTOS task (drains ssh_to_usb → CDC TX).
 * Call after usb_cdc_init().
 */
esp_err_t usb_cdc_start_task(void);

#ifdef __cplusplus
}
#endif
