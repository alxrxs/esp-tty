/*
 * main.c — app_main: NVS init, ring buffer allocation, task spawn
 */

#include "esp_log.h"
#include "esp_partition.h"
#include "nvs_flash.h"

#include "ring.h"
#include "wifi.h"
#include "usb_cdc.h"
#include "ssh_server.h"

static const char *TAG = "main";

/* 16 KB ring buffers allocated in PSRAM (8 MB available on N16R8).
   Both allocated here so app_main owns their lifetimes. */
#define RING_SIZE (16 * 1024)

void app_main(void)
{
    /* ── 1. NVS flash init with encryption ─────────────────────────
     * AES-XTS-256 key is generated on first boot and stored in the
     * nvs_keys partition (see partitions.csv).  No eFuses are burned.
     * Protection level: stops partial-partition dumps; a full flash
     * dump still exposes the key.  Flash encryption (burns eFuses)
     * would close that gap but is outside this project's scope.
     */
    /* Use the v1 NVS security API: keys are generated at first boot and
     * written to the nvs_keys partition.  No eFuses are burned.
     * nvs_sec_provider / Kconfig flash-enc scheme is NOT used here — that
     * would require CONFIG_SECURE_FLASH_ENC_ENABLED (burns eFuses). */
    const esp_partition_t *keys_part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, NULL);
    if (!keys_part) {
        ESP_LOGE(TAG, "nvs_keys partition not found — check partitions.csv");
        abort();
    }

    nvs_sec_cfg_t nvs_sec_cfg;
    esp_err_t err = nvs_flash_read_security_cfg(keys_part, &nvs_sec_cfg);
    if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED ||
        err == ESP_ERR_NVS_CORRUPT_KEY_PART) {
        ESP_LOGI(TAG, "NVS keys not found — generating new AES-XTS-256 key");
        ESP_ERROR_CHECK(nvs_flash_generate_keys(keys_part, &nvs_sec_cfg));
    } else {
        ESP_ERROR_CHECK(err);
    }

    err = nvs_flash_secure_init_partition("nvs", &nvs_sec_cfg);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase — erasing and re-init with encryption");
        const esp_partition_t *nvs_part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
        ESP_ERROR_CHECK(esp_partition_erase_range(nvs_part, 0, nvs_part->size));
        err = nvs_flash_secure_init_partition("nvs", &nvs_sec_cfg);
    }
    ESP_ERROR_CHECK(err);
    ESP_LOGI(TAG, "NVS initialised (AES-XTS-256 encrypted)");

    /* ── 2. Shared ring buffers (PSRAM) ──────────────────────────── */
    ring_t *usb_to_ssh = ring_create(RING_SIZE);
    ring_t *ssh_to_usb = ring_create(RING_SIZE);
    if (!usb_to_ssh || !ssh_to_usb) {
        ESP_LOGE(TAG, "Failed to allocate ring buffers in PSRAM");
        abort();
    }
    ESP_LOGI(TAG, "Ring buffers allocated (%d KB each in PSRAM)",
             RING_SIZE / 1024);

    /* ── 3. USB CDC ACM (Linux host serial port) ─────────────────── */
#ifndef BRIDGE_LOOPBACK
    ESP_ERROR_CHECK(usb_cdc_init(usb_to_ssh, ssh_to_usb));
    ESP_ERROR_CHECK(usb_cdc_start_task());
    ESP_LOGI(TAG, "USB CDC ACM ready — plug USB-C cable to native USB port");
#else
    /* Wokwi / CI loopback: usb_to_ssh and ssh_to_usb are wired together
       by the bridge pump directly; no TinyUSB involved. */
    ESP_LOGI(TAG, "BRIDGE_LOOPBACK mode — USB CDC bypassed");
#endif

    /* ── 4. Wi-Fi STA ────────────────────────────────────────────── */
    err = wifi_init_sta();
    if (err != ESP_OK) {
        /* wifi.c keeps retrying; SSH server starts anyway in case an
           existing TCP session was pre-established during the grace window. */
        ESP_LOGW(TAG, "wifi_init_sta returned error — SSH server starting anyway");
    }

    /* ── 5. SSH server ───────────────────────────────────────────── */
    /* host_key_load_or_generate needs Wi-Fi up for hardware RNG entropy.
       The assignment above ensures Wi-Fi start() has been called even
       if IP acquisition failed. */
    ESP_ERROR_CHECK(ssh_server_start(usb_to_ssh, ssh_to_usb));

    ESP_LOGI(TAG, "All tasks running — device ready");
}
