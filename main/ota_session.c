/*
 * ota_session.c -- OTA firmware update over SSH channel for esp-tty
 *
 * Linked from ssh_server.c when username == "ota".
 * Streams the OTA image from the SSH channel into ota_verify, which
 * decrypts and writes it to the inactive OTA partition.
 *
 * Key material:
 *   - ECDSA-P256 public key  : embedded from ota_keys/sign.pub.pem
 *                              via EMBED_TXTFILES -> _binary_sign_pub_pem_start
 *   - AES-256 raw key (32B)  : embedded from ota_keys/aes.key
 *                              via EMBED_FILES -> _binary_aes_key_start
 *
 * Security:
 *   - SSH layer provides transport encryption and pubkey authentication.
 *   - OTA layer adds an independent ECDSA-P256 sig + AES-GCM authentication
 *     gate so a compromised SSH key cannot deliver a bad firmware image.
 *   - If either gate fails, esp_ota_set_boot_partition() is NOT called and
 *     the device continues running the current firmware.
 */

#include "ota_session.h"
#include "ota_verify.h"
#include "ota_stream.h"
#include "config.h"   /* OTA_AUTHORIZED_PUBKEY */

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wolfssh/ssh.h"

static const char *TAG = "ota_session";

/* -- Embedded key material ------------------------------------------------- */
/* Symbols injected by CMake EMBED_TXTFILES / EMBED_FILES.
 * Only present when ota_keys/sign.pub.pem and ota_keys/aes.key exist at
 * build time.  When absent, OTA_KEYS_EMBEDDED is not defined and
 * ota_session_handler() returns an error without referencing them. */
#ifdef OTA_KEYS_EMBEDDED
extern const uint8_t _binary_sign_pub_pem_start[];
extern const uint8_t _binary_sign_pub_pem_end[];
extern const uint8_t _binary_aes_key_start[];
extern const uint8_t _binary_aes_key_end[];
#endif

/* Maximum total OTA image size we will accept.  The flash OTA partitions
 * are ~4 MiB; allow some headroom for the OTA wrapper (44-byte header +
 * 64-byte signature ~= 108 bytes) but cap below the 8 MiB PSRAM ceiling. */
#define MAX_OTA_SIZE             (6u * 1024u * 1024u)

/* How many WS_WANT_READ-induced "transient 0-return" events the
 * ota_stream accumulator should tolerate before giving up.  Each transient
 * triggers a 10 ms vTaskDelay inside wolfssh_read_adapter, so 60000 ~=
 * 10 minutes of total idle before the session is considered dead -- well
 * past the original infinite-retry behaviour for realistic uploads. */
#define MAX_OTA_ZERO_RETRIES     60000u

/* -- Helper: send a short text reply to the SSH client -------------------- */
static void ssh_send_reply(WOLFSSH *ssh, const char *msg)
{
    wolfSSH_stream_send(ssh, (byte *)msg, (word32)strlen(msg));
}

/* -- ota_stream adapter: wolfSSH_stream_read -> ota_stream_read_fn ---------
 *
 *   > 0           -> bytes read
 *   WS_WANT_READ  -> return 0 (transient); the accumulator's retry budget
 *                   plus the vTaskDelay below mimic the original
 *                   "sleep 10 ms and retry" hot loop.
 *   <= 0 other    -> return -1 (terminal EOF/error)
 */
static int wolfssh_read_adapter(void *ctx, uint8_t *buf, size_t cap)
{
    WOLFSSH *ssh = (WOLFSSH *)ctx;
    int n = wolfSSH_stream_read(ssh, (byte *)buf, (word32)cap);
    if (n == WS_WANT_READ) {
        vTaskDelay(pdMS_TO_TICKS(10));
        return 0;
    }
    if (n <= 0) return -1;
    return n;
}

/* -- PSRAM-backed allocator hooks for ota_stream -------------------------
 *
 * The OTA image is potentially several MiB so the buffer must live in PSRAM,
 * not internal SRAM.  ota_stream uses alloc + realloc (or just realloc if
 * we pass NULL for alloc and the first realloc(NULL, n) call falls through
 * -- but heap_caps_realloc accepts NULL for the old pointer, so we expose
 * realloc-via-NULL as the initial-allocation path and keep alloc_fn NULL... )
 *
 * Cleaner: provide explicit wrappers for both so the caller flow is obvious
 * and so the free path uses the matching heap_caps_free.  heap_caps_malloc /
 * heap_caps_realloc / heap_caps_free all use the same MALLOC_CAP_SPIRAM pool.
 */
static void *psram_alloc(size_t n)
{
    return heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
}
static void *psram_realloc(void *p, size_t n)
{
    return heap_caps_realloc(p, n, MALLOC_CAP_SPIRAM);
}
static void  psram_free(void *p)
{
    heap_caps_free(p);
}

/* -- OTA session handler --------------------------------------------------- */

esp_err_t ota_session_handler(WOLFSSH *ssh)
{
    ESP_LOGI(TAG, "OTA session started");

#ifndef OTA_KEYS_EMBEDDED
    /* Keys were not embedded at build time -- refuse the session gracefully. */
    ESP_LOGE(TAG, "OTA key material not embedded in firmware -- build with ota_keys/sign.pub.pem and ota_keys/aes.key");
    ssh_send_reply(ssh, "OTA_ERR: key material not embedded in firmware\n");
    return ESP_ERR_INVALID_STATE;
#else

    /* Determine public key and AES key sizes */
    size_t pub_pem_len = (size_t)(_binary_sign_pub_pem_end - _binary_sign_pub_pem_start);
    size_t aes_key_len = (size_t)(_binary_aes_key_end      - _binary_aes_key_start);

    if (pub_pem_len == 0 || aes_key_len != 32) {
        ESP_LOGE(TAG, "OTA key material invalid: pub_pem_len=%zu aes_key_len=%zu",
                 pub_pem_len, aes_key_len);
        ssh_send_reply(ssh, "OTA_ERR: key material not embedded in firmware\n");
        return ESP_ERR_INVALID_STATE;
    }

    /* pub_pem must be NUL-terminated for mbedtls_pk_parse_public_key.
       EMBED_TXTFILES normally appends a NUL byte, so pub_pem_len includes it. */
    const uint8_t *pub_pem = _binary_sign_pub_pem_start;

    /* Begin OTA verify session */
    ota_verify_ctx_t *ctx = ota_verify_begin(pub_pem, pub_pem_len, _binary_aes_key_start);
    if (!ctx) {
        ESP_LOGE(TAG, "ota_verify_begin failed (OOM or bad key)");
        ssh_send_reply(ssh, "OTA_ERR: failed to initialise verifier\n");
        return ESP_ERR_NO_MEM;
    }

    /* Stream the OTA image from the SSH channel into a PSRAM-backed
     * growable buffer.  We don't know the image length in advance, so we
     * read until wolfSSH_stream_read returns <= 0 (EOF or channel close).
     *
     * The growable-buffer logic lives in lib/ota_stream/ so it is native-
     * unit-tested without wolfSSH or ESP-IDF.  Here we just supply:
     *   - wolfssh_read_adapter : translate WS_WANT_READ -> 0 (transient).
     *   - psram_*              : place the buffer in PSRAM, NOT internal SRAM.
     *
     * On S3 with 8 MB PSRAM, MAX_OTA_SIZE (6 MiB) comfortably handles any
     * realistic firmware image (4 MB partition -> max ~4 MB signed image).
     */
    uint8_t *image_buf = NULL;
    size_t   image_len = 0;

    ota_stream_result_t sr = ota_stream_read_all(
        wolfssh_read_adapter, ssh,
        MAX_OTA_SIZE,
        MAX_OTA_ZERO_RETRIES,
        psram_alloc, psram_realloc, psram_free,
        &image_buf, &image_len);

    if (sr != OTA_STREAM_OK) {
        if (sr == OTA_STREAM_ERR_OOM) {
            ESP_LOGE(TAG, "OOM reading OTA image");
        } else if (sr == OTA_STREAM_ERR_TOOBIG) {
            ESP_LOGE(TAG, "OTA image exceeds MAX_OTA_SIZE (%u bytes)",
                     (unsigned)MAX_OTA_SIZE);
        } else {
            ESP_LOGE(TAG, "OTA stream read failed: %d", (int)sr);
        }
        ota_verify_abort(ctx);
        ssh_send_reply(ssh, "OTA_ERR: failed to read image or image empty\n");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Received %zu bytes -- verifying...", image_len);

    /* Feed the full image to the verifier */
    ota_verify_err_t e = ota_verify_feed(ctx, image_buf, image_len, image_len);
    psram_free(image_buf);

    if (e != OTA_VERIFY_OK) {
        ota_verify_abort(ctx);
        char reply[64];
        snprintf(reply, sizeof(reply), "OTA_ERR: %s\n", ota_verify_strerror(e));
        ssh_send_reply(ssh, reply);
        ESP_LOGE(TAG, "OTA verify feed failed: %s", ota_verify_strerror(e));
        return ESP_FAIL;
    }

    e = ota_verify_end(ctx);
    if (e != OTA_VERIFY_OK) {
        char reply[64];
        snprintf(reply, sizeof(reply), "OTA_ERR: %s\n", ota_verify_strerror(e));
        ssh_send_reply(ssh, reply);
        ESP_LOGE(TAG, "OTA verify end failed: %s", ota_verify_strerror(e));
        return ESP_FAIL;
    }

    /* Success -- confirm to client, then reboot */
    ssh_send_reply(ssh, "OTA_OK\n");
    wolfSSH_shutdown(ssh);

    ESP_LOGI(TAG, "OTA image accepted -- rebooting in 2 seconds");
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return ESP_OK; /* unreachable */
#endif /* OTA_KEYS_EMBEDDED */
}
