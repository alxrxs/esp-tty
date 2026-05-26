/*
 * main.c -- app_main: NVS init, ring buffer allocation, task spawn
 */

/* config.h MUST precede project-internal headers because several of them
 * (wifi.h, cert_renewer.h) gate their public declarations on macros
 * defined in config.h (notably WIFI_ENTERPRISE_SSID). */
#include "config.h"

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"

#include "ring.h"
#include "scrollback.h"
#include "wifi.h"
#include "usb_cdc.h"
#include "ssh_server.h"
#include "rollback_decision.h"
#include "scep_enroll.h"
#ifdef WIFI_ENTERPRISE_SSID
#include "cert_renewer.h"
#endif
/* mbedTLS bench-only includes: only rsa_bench_task uses these.  Gated so
 * the production app_main path does not pull in private headers it does
 * not need. */
#ifdef SCEP_KEYGEN_BENCH_ON_BOOT
#include "mbedtls/build_info.h"
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
/* mbedTLS 4.x: private/ headers for legacy crypto contexts.
 * MBEDTLS_ALLOW_PRIVATE_ACCESS (from ESP-IDF mbedtls esp_config.h) → private_access.h defines
 * MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS which unlocks function declarations. */
#include "mbedtls/private/pk_private.h"
#include "mbedtls/private/rsa.h"
/* mbedtls_esp_random() is declared in esp_mbedtls_random.h but its
 * implementation was omitted from the esp-idf 6.0.1 mbedtls port in
 * PlatformIO espressif32@7.0.1.  Use esp_fill_random directly instead. */
#include "esp_random.h"
static int main_esp_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}
#else
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#endif
#include "mbedtls/pk.h"
#endif /* SCEP_KEYGEN_BENCH_ON_BOOT */

static const char *TAG = "main";

/* SCEP_SMOKE_TEST_ON_BOOT: quick re-verify hook for development.
 *
 * WARNING: this fires on every boot, unconditionally re-enrolling even when
 * valid credentials exist.  Each re-enrollment consumes an NDES OTP challenge
 * and creates a new audit-log entry on the CA.  Leave this UNDEFINED in
 * production firmware; it is a development-only diagnostic tool. */
#ifdef SCEP_SMOKE_TEST_ON_BOOT
void scep_smoke_task(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "SCEP smoke test: enrolling now against %s", SCEP_URL);
    TickType_t t0 = xTaskGetTickCount();
    esp_err_t scep_rc = scep_enroll(SCEP_URL, SCEP_CHALLENGE_PASSWORD, NULL);
    TickType_t t1 = xTaskGetTickCount();
    ESP_LOGW(TAG, "SCEP smoke test: result=%s (0x%x) elapsed=%lu ms",
             esp_err_to_name(scep_rc), (unsigned)scep_rc,
             (unsigned long)((t1 - t0) * portTICK_PERIOD_MS));
    vTaskDelete(NULL);
}
#endif

#ifdef SCEP_KEYGEN_BENCH_ON_BOOT
void rsa_bench_task(void *arg)
{
    (void)arg;
    mbedtls_pk_context pk;
    TickType_t t0, t1;

    mbedtls_pk_init(&pk);

    int rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (rc != 0) {
        ESP_LOGE(TAG, "keygen bench: pk_setup failed: -0x%04x", (unsigned)(-rc));
        goto bench_done;
    }
    ESP_LOGW(TAG, "RSA-2048 keygen bench: starting...");
    t0 = xTaskGetTickCount();
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), main_esp_rng, NULL, 2048, 65537);
#else
    {
        mbedtls_entropy_context  entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)"bench", 5);
        rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random,
                                  &ctr_drbg, 2048, 65537);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
#endif
    t1 = xTaskGetTickCount();
    ESP_LOGW(TAG, "RSA-2048 keygen bench: rc=-0x%04x elapsed=%lu ms",
             (unsigned)(-rc), (unsigned long)((t1 - t0) * portTICK_PERIOD_MS));

bench_done:
    mbedtls_pk_free(&pk);
    vTaskDelete(NULL);
}
#endif

/* Per-direction ring buffer size.  Defaults differ between PSRAM-equipped
 * and internal-RAM-only boards: PSRAM has plenty of room for 16 KB each,
 * internal RAM is tight so 4 KB is a sensible cap.  Override in config.h
 * if you need more headroom (and have the RAM for it). */
#ifndef RING_BUFFER_BYTES
# ifdef CONFIG_SPIRAM
#  define RING_BUFFER_BYTES (16 * 1024)
# else
#  define RING_BUFFER_BYTES (4 * 1024)
# endif
#endif

/* Scrollback capacity.  PSRAM build keeps 128 KB; no-PSRAM build drops to
 * 8 KB so the scrollback fits alongside the WiFi/TLS heap usage in
 * internal RAM. */
#ifndef SCROLLBACK_BUFFER_BYTES
# ifdef CONFIG_SPIRAM
#  define SCROLLBACK_BUFFER_BYTES (128 * 1024)
# else
#  define SCROLLBACK_BUFFER_BYTES (8 * 1024)
# endif
#endif

/* -- Rollback self-test ---------------------------------------------------
 * After CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y, newly booted firmware is
 * in ESP_OTA_IMG_PENDING_VERIFY state.  If the app crashes or WDT fires
 * before marking valid, the bootloader rolls back to the previous image.
 *
 * We mark valid after this many milliseconds of successful SSH server
 * operation. The one-shot timer fires from a FreeRTOS timer task
 * (not app_main). */
#ifndef OTA_ROLLBACK_DELAY_MS
#define OTA_ROLLBACK_DELAY_MS 30000
#endif

static void rollback_timer_cb(TimerHandle_t xTimer)
{
    (void)xTimer;
    esp_ota_img_states_t state;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (esp_ota_get_state_partition(running, &state) != ESP_OK)
        return;
    if (rollback_decide(state) == ROLLBACK_DECISION_MARK_VALID) {
        ESP_LOGI("main", "Marking OTA image valid (rollback cancelled)");
        esp_ota_mark_app_valid_cancel_rollback();
    }
    /* If not PENDING_VERIFY (factory or already valid), this is a no-op */
}

void app_main(void)
{
    /* -- 1. NVS flash init with encryption -------------------------
     * AES-XTS-256 key is generated on first boot and stored in the
     * nvs_keys partition (see partitions.csv).  No eFuses are burned.
     * Protection level: stops partial-partition dumps; a full flash
     * dump still exposes the key.  Flash encryption (burns eFuses)
     * would close that gap but is outside this project's scope.
     */
    /* Use the v1 NVS security API: keys are generated at first boot and
     * written to the nvs_keys partition.  No eFuses are burned.
     * nvs_sec_provider / Kconfig flash-enc scheme is NOT used here -- that
     * would require CONFIG_SECURE_FLASH_ENC_ENABLED (burns eFuses). */
    const esp_partition_t *keys_part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, NULL);
    if (!keys_part) {
        ESP_LOGE(TAG, "nvs_keys partition not found -- check partitions.csv");
        abort();
    }

    nvs_sec_cfg_t nvs_sec_cfg;
    esp_err_t err = nvs_flash_read_security_cfg(keys_part, &nvs_sec_cfg);
    if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED ||
        err == ESP_ERR_NVS_CORRUPT_KEY_PART) {
        ESP_LOGI(TAG, "NVS keys not found -- generating new AES-XTS-256 key");
        ESP_ERROR_CHECK(nvs_flash_generate_keys(keys_part, &nvs_sec_cfg));
    } else {
        ESP_ERROR_CHECK(err);
    }

    err = nvs_flash_secure_init_partition("nvs", &nvs_sec_cfg);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase -- erasing and re-init with encryption");
        const esp_partition_t *nvs_part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
        ESP_ERROR_CHECK(esp_partition_erase_range(nvs_part, 0, nvs_part->size));
        err = nvs_flash_secure_init_partition("nvs", &nvs_sec_cfg);
    }
    ESP_ERROR_CHECK(err);
    ESP_LOGI(TAG, "NVS initialised (AES-XTS-256 encrypted)");

    /* -- 2. Shared ring buffers + scrollback (PSRAM) --------------- */
    ring_t *usb_to_ssh = ring_create(RING_BUFFER_BYTES);
    ring_t *ssh_to_usb = ring_create(RING_BUFFER_BYTES);
    if (!usb_to_ssh || !ssh_to_usb) {
        ESP_LOGE(TAG, "Failed to allocate ring buffers in PSRAM");
        abort();
    }
    ESP_LOGI(TAG, "Ring buffers allocated (%d KB each, %s)",
             RING_BUFFER_BYTES / 1024,
#ifdef CONFIG_SPIRAM
             "PSRAM"
#else
             "internal RAM"
#endif
            );

    scrollback_t *scrollback = scrollback_create(SCROLLBACK_BUFFER_BYTES);
    if (!scrollback) {
        /* Non-fatal: SSH sessions work, just no replay on connect. */
        ESP_LOGW(TAG, "scrollback_create failed -- continuing without replay");
    } else {
        ESP_LOGI(TAG, "Scrollback buffer allocated (%u KB, %s)",
                 (unsigned)(SCROLLBACK_BUFFER_BYTES / 1024),
#ifdef CONFIG_SPIRAM
                 "PSRAM"
#else
                 "internal RAM"
#endif
                );
    }

    /* -- 3. USB CDC ACM (Linux host serial port) ------------------- */
#if defined(BRIDGE_LOOPBACK)
    /* Wokwi / CI loopback: usb_to_ssh and ssh_to_usb are wired together
       by the bridge pump directly; no TinyUSB involved. */
    ESP_LOGI(TAG, "BRIDGE_LOOPBACK mode -- USB CDC bypassed");
#elif defined(USB_DEBUG_CONSOLE_ONLY)
    /* Debug-console mode: USB-OTG is not initialised so the USB-Serial-JTAG
       controller owns GPIO19/20.  ESP_LOG* output streams from the USB-C port
       as a 303a:1001 CDC ACM device -- no SSH bridge in this build. */
    ESP_LOGI(TAG, "USB_DEBUG_CONSOLE_ONLY -- TinyUSB skipped, logs via USB-Serial-JTAG");
#else
    ESP_ERROR_CHECK(usb_cdc_init(usb_to_ssh, ssh_to_usb, scrollback));
    ESP_ERROR_CHECK(usb_cdc_start_task());
    ESP_LOGI(TAG, "USB CDC ACM ready -- plug USB-C cable to native USB port");
#endif

#ifdef SCEP_KEYGEN_BENCH_ON_BOOT
    /* Pre-Wi-Fi RSA-2048 keygen timing.  Runs in a dedicated 32KB-stack
       task because RSA bignum scratch (~4-8 KB even with WOLFSSL_SMALL_STACK)
       overflows the default main_task stack.  Doesn't need network. */
    extern void rsa_bench_task(void *);
    {
        BaseType_t bench_rc = xTaskCreate(rsa_bench_task, "rsa_bench",
                                          32768, NULL, 5, NULL);
        if (bench_rc != pdPASS)
            ESP_LOGW(TAG, "rsa_bench_task create failed (no mem?) -- skipping bench");
    }
#endif

    /* -- 4. Wi-Fi STA ---------------------------------------------- */
#if defined(WIFI_ENTERPRISE_SSID) && defined(WIFI_USE_ENTERPRISE)
    /* Mode B+: embedded certs + PSK bootstrap for NTP sync before EAP-TLS.
     * No SCEP; no cert renewer.  Only when both macros are defined. */
    err = wifi_init_enterprise_bootstrap();
#elif defined(WIFI_ENTERPRISE_SSID)
    /* Mode C: PSK bootstrap + SCEP enrollment + EAP-TLS. */
    err = wifi_init_smart();
#else
    err = wifi_init_sta();
#endif
    if (err != ESP_OK) {
        /* wifi.c keeps retrying; SSH server starts anyway in case an
           existing TCP session was pre-established during the grace window. */
        ESP_LOGW(TAG, "wifi_init returned error -- SSH server starting anyway");
    }

#ifdef SCEP_SMOKE_TEST_ON_BOOT
    /* SCEP enrollment smoke test (post-Wi-Fi).  Spawned into a 32KB-stack
       task because scep_enroll's PKCS#7 + CSR + bignum scratch overflows
       the default main_task stack and panics with IllegalInstruction.
       Same reason as the keygen bench task above. */
    extern void scep_smoke_task(void *);
    if (err == ESP_OK) {
        xTaskCreate(scep_smoke_task, "scep_smoke", 32768, NULL, 5, NULL);
    }
#endif

#if defined(WIFI_ENTERPRISE_SSID) && defined(SCEP_URL) && !defined(WIFI_USE_ENTERPRISE)
    /* Certificate renewal watchdog (Mode C only -- Mode B+ uses embedded
     * certs that cannot be renewed via SCEP).  Guard MUST match
     * cert_renewer.h's #if exactly; otherwise this call site references
     * an undeclared symbol on a future config that defines
     * WIFI_ENTERPRISE_SSID without SCEP_URL. */
    if (err == ESP_OK) {
        esp_err_t renewer_err = cert_renewer_start();
        if (renewer_err != ESP_OK) {
            ESP_LOGW(TAG, "cert_renewer_start failed -- renewal will not run");
        }
    }
#endif

    /* -- 5. SSH server --------------------------------------------- */
    /* host_key_load_or_generate needs Wi-Fi up for hardware RNG entropy.
       The assignment above ensures Wi-Fi start() has been called even
       if IP acquisition failed. */
    ESP_ERROR_CHECK(ssh_server_start(usb_to_ssh, ssh_to_usb, scrollback));

    /* -- 6. Rollback self-test timer -------------------------------------- */
    /* One-shot 30-second timer: if the SSH server is still running by then,
       we consider the image valid and cancel pending rollback. */
    TimerHandle_t rollback_timer = xTimerCreate(
        "rollback", pdMS_TO_TICKS(OTA_ROLLBACK_DELAY_MS),
        pdFALSE,    /* one-shot */
        NULL,
        rollback_timer_cb);
    if (rollback_timer) {
        xTimerStart(rollback_timer, 0);
        ESP_LOGI(TAG, "Rollback timer started (%d ms)", OTA_ROLLBACK_DELAY_MS);
    } else {
        ESP_LOGW(TAG, "Failed to create rollback timer -- calling mark_valid now");
        esp_ota_mark_app_valid_cancel_rollback();
    }

    ESP_LOGI(TAG, "All tasks running -- device ready");
}
