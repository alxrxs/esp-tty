/*
 * ota_session.c — OTA firmware update over SSH channel for esp-tty
 *
 * Linked from ssh_server.c when username == "ota".
 * Streams the OTA image from the SSH channel into ota_verify, which
 * decrypts and writes it to the inactive OTA partition.
 *
 * Key material:
 *   - ECDSA-P256 public key  : embedded from ota_keys/sign.pub.pem
 *                              via EMBED_TXTFILES → _binary_sign_pub_pem_start
 *   - AES-256 raw key (32B)  : embedded from ota_keys/aes.key
 *                              via EMBED_FILES → _binary_aes_key_start
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

/* ── Embedded key material ───────────────────────────────────────────────── */
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

/* ── Read/write chunk size ───────────────────────────────────────────────── */
#define OTA_READ_CHUNK  2048

/* ── Helper: send a short text reply to the SSH client ──────────────────── */
static void ssh_send_reply(WOLFSSH *ssh, const char *msg)
{
    wolfSSH_stream_send(ssh, (byte *)msg, (word32)strlen(msg));
}

/* ── OTA session handler ─────────────────────────────────────────────────── */

esp_err_t ota_session_handler(WOLFSSH *ssh)
{
    ESP_LOGI(TAG, "OTA session started");

#ifndef OTA_KEYS_EMBEDDED
    /* Keys were not embedded at build time — refuse the session gracefully. */
    ESP_LOGE(TAG, "OTA key material not embedded in firmware — build with ota_keys/sign.pub.pem and ota_keys/aes.key");
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

    /* Allocate read buffer on the heap (stack is limited in SSH task) */
    uint8_t *buf = malloc(OTA_READ_CHUNK);
    if (!buf) {
        ota_verify_abort(ctx);
        ssh_send_reply(ssh, "OTA_ERR: OOM\n");
        return ESP_ERR_NO_MEM;
    }

    /* Stream the OTA image from the SSH channel.
     * We don't know the image length in advance, so we read until EOF
     * (wolfSSH_stream_read returns WS_EOF or <= 0 after the channel closes).
     * total_image_len is passed as 0 on the first call; ota_verify_feed
     * accepts this on first call and we update when we find out the actual
     * size (not possible without knowing it upfront).
     *
     * Protocol: the client sends exactly image_len bytes then closes the
     * write side.  We detect EOF and call ota_verify_end().
     *
     * Note: we accumulate the total length as we go and re-pass it each time.
     * Since we pass total_image_len=0 until EOF, ota_verify will reject on
     * the first feed call.  Instead, we buffer or use a two-pass scheme.
     *
     * Simplest correct approach: read everything into a heap buffer (PSRAM
     * available), then do one call.  On S3 with 8MB PSRAM this handles any
     * realistic firmware image (4MB partition, so max ~4MB signed image).
     */

    /* Use a growable buffer in PSRAM for the full image */
    uint8_t *image_buf = NULL;
    size_t   image_len = 0;
    size_t   image_cap = 0;

    bool read_error = false;
    while (1) {
        int n = wolfSSH_stream_read(ssh, buf, OTA_READ_CHUNK);
        if (n == WS_WANT_READ) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (n <= 0) {
            /* EOF or error */
            break;
        }

        /* Grow buffer if needed */
        if (image_len + (size_t)n > image_cap) {
            size_t new_cap = (image_cap == 0) ? (OTA_READ_CHUNK * 8) : (image_cap * 2);
            if (new_cap < image_len + (size_t)n)
                new_cap = image_len + (size_t)n;
            uint8_t *new_buf = heap_caps_realloc(image_buf, new_cap, MALLOC_CAP_SPIRAM);
            if (!new_buf) {
                /* PSRAM exhausted — this is a hard OOM (8 MB PSRAM, 4 MB max image).
                 * Do NOT fall back to realloc(): image_buf was allocated from PSRAM
                 * and realloc() does not know that, which causes undefined behavior
                 * (heap corruption) on ESP-IDF. Treat as a real, unrecoverable OOM. */
                ESP_LOGE(TAG, "OOM reading OTA image (have %zu bytes so far)", image_len);
                read_error = true;
                break;
            }
            image_buf = new_buf;
            image_cap = new_cap;
        }
        memcpy(image_buf + image_len, buf, n);
        image_len += (size_t)n;
    }
    free(buf);

    if (read_error || image_len == 0) {
        free(image_buf);
        ota_verify_abort(ctx);
        ssh_send_reply(ssh, "OTA_ERR: failed to read image or image empty\n");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Received %zu bytes — verifying...", image_len);

    /* Feed the full image to the verifier */
    ota_verify_err_t e = ota_verify_feed(ctx, image_buf, image_len, image_len);
    free(image_buf);

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

    /* Success — confirm to client, then reboot */
    ssh_send_reply(ssh, "OTA_OK\n");
    wolfSSH_shutdown(ssh);

    ESP_LOGI(TAG, "OTA image accepted — rebooting in 2 seconds");
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return ESP_OK; /* unreachable */
#endif /* OTA_KEYS_EMBEDDED */
}
