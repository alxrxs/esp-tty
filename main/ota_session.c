/*
 * ota_session.c -- OTA firmware update over SSH channel for esp-tty
 *
 * Linked from ssh_server.c when username == "ota".
 *
 * Wire protocol (over an authenticated SSH ota@ channel):
 *
 *   Device -> Client: [0x02] [32B device_ephemeral_x25519_pub]
 *   Client -> Device: [32B client_ephemeral_x25519_pub]
 *
 *   Both sides derive:
 *     shared = X25519(own_priv, peer_pub)                  // 32 B
 *     key    = HKDF-SHA256(ikm=shared,
 *                          salt="esp-tty-ota-v2",
 *                          info=client_pub || device_pub,
 *                          L=32)
 *
 *   Client -> Device: [4B plaintext_len LE] [12B IV] [16B tag] [N B ciphertext]
 *   Device -> Client: 0x00                            (success, about to reboot)
 *                  or 0xFF + "<ascii reason>\n"       (failure, no reboot)
 *
 * AES-256-GCM with empty AAD; tag covers ciphertext only.
 * Curve25519 keys use the little-endian (RFC 7748) convention on both sides.
 *
 * SSH layer already provides mutual authentication via OTA_AUTHORIZED_PUBKEY;
 * the inner key exchange just adds an independent encryption layer with no
 * pre-shared key material baked into the firmware.
 */

#include "ota_session.h"
#include "config.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "zeroize.h"

#include "wolfssh/ssh.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

static const char *TAG = "ota_session";

#define OTA_PROTO_VERSION   0x02
#define X25519_KEY_LEN      32
#define OTA_IV_LEN          12
#define OTA_TAG_LEN         16
#define OTA_AES_KEY_LEN     32

/* Hard cap on plaintext firmware size.  ota_0 / ota_1 are ~4 MiB; we cap
 * below the 8 MiB PSRAM ceiling so the ciphertext buffer fits. */
#define MAX_OTA_PLAINTEXT   (4u * 1024u * 1024u)

/* Idle / channel-dead detection: WS_WANT_READ retries with a 10 ms delay,
 * capped at MAX_READ_RETRIES = 3000 retries * 10 ms = 30 s total idle timeout.
 * 30 s matches a typical SSH handshake / channel-open timeout; the previous
 * 60 000 (10 min) value allowed a slow-read DoS. */
#define READ_POLL_MS        10
#define MAX_READ_RETRIES    3000u

static const byte HKDF_SALT[] = "esp-tty-ota-v2"; /* 14 bytes, no NUL */
#define HKDF_SALT_LEN  (sizeof(HKDF_SALT) - 1)

/* -- small helpers --------------------------------------------------------- */

static int ssh_send_all(WOLFSSH *ssh, const void *buf, size_t len)
{
    const byte *p = (const byte *)buf;
    size_t      remaining = len;
    unsigned    spins = 0;

    while (remaining > 0) {
        int n = wolfSSH_stream_send(ssh, (byte *)p, (word32)remaining);
        if (n == WS_WANT_WRITE || n == WS_WANT_READ) {
            if (++spins > MAX_READ_RETRIES) return -1;
            vTaskDelay(pdMS_TO_TICKS(READ_POLL_MS));
            continue;
        }
        if (n <= 0) return -1;
        p += n;
        remaining -= (size_t)n;
        spins = 0;
    }
    return 0;
}

/* Read exactly len bytes from the SSH channel, blocking with retries on
 * WS_WANT_READ.  Returns 0 on success, -1 on EOF/error/timeout. */
static int ssh_read_exact(WOLFSSH *ssh, void *buf, size_t len)
{
    byte    *p = (byte *)buf;
    size_t   remaining = len;
    unsigned spins = 0;

    while (remaining > 0) {
        int n = wolfSSH_stream_read(ssh, p, (word32)remaining);
        if (n == WS_WANT_READ) {
            if (++spins > MAX_READ_RETRIES) return -1;
            vTaskDelay(pdMS_TO_TICKS(READ_POLL_MS));
            continue;
        }
        if (n <= 0) return -1;
        p += n;
        remaining -= (size_t)n;
        spins = 0;
    }
    return 0;
}

static void send_failure(WOLFSSH *ssh, const char *reason)
{
    byte b = 0xFF;
    ssh_send_all(ssh, &b, 1);
    if (reason && *reason) {
        ssh_send_all(ssh, reason, strlen(reason));
        ssh_send_all(ssh, "\n", 1);
    }
}

/* DMA-capable scratch (internal SRAM, word-aligned) for AES-GCM context.
 * The ciphertext buffer itself lives in PSRAM; wolfSSL's SW path handles
 * that fine even with the HW accelerator engaged (the driver copies into
 * its own DMA buffer in chunks).  Tag and IV are small stack values. */

/* -- OTA session handler --------------------------------------------------- */

esp_err_t ota_session_handler(WOLFSSH *ssh)
{
    ESP_LOGI(TAG, "OTA session started (v2 X25519+AES-GCM)");

    int           rc;
    WC_RNG        rng;
    curve25519_key dev_key;
    curve25519_key cli_key;
    int           rng_init = 0;
    int           dev_key_init = 0;
    int           cli_key_init = 0;
    uint8_t      *ciphertext = NULL;
    esp_ota_handle_t ota_handle = 0;
    bool          ota_began = false;

    /* ---- 1. Generate ephemeral device keypair ---------------------- */
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        ESP_LOGE(TAG, "wc_InitRng failed: %d", rc);
        send_failure(ssh, "rng init failed");
        goto out;
    }
    rng_init = 1;

    rc = wc_curve25519_init(&dev_key);
    if (rc != 0) {
        ESP_LOGE(TAG, "wc_curve25519_init(dev) failed: %d", rc);
        send_failure(ssh, "x25519 init failed");
        goto out;
    }
    dev_key_init = 1;

    rc = wc_curve25519_make_key(&rng, X25519_KEY_LEN, &dev_key);
    if (rc != 0) {
        ESP_LOGE(TAG, "wc_curve25519_make_key failed: %d", rc);
        send_failure(ssh, "x25519 keygen failed");
        goto out;
    }

    uint8_t dev_pub[X25519_KEY_LEN];
    word32  dev_pub_len = sizeof(dev_pub);
    rc = wc_curve25519_export_public_ex(&dev_key, dev_pub, &dev_pub_len,
                                        EC25519_LITTLE_ENDIAN);
    if (rc != 0 || dev_pub_len != X25519_KEY_LEN) {
        ESP_LOGE(TAG, "export_public failed: %d", rc);
        send_failure(ssh, "x25519 export failed");
        goto out;
    }

    /* ---- 2. Send [version] [device pub] ---------------------------- */
    {
        uint8_t hdr[1 + X25519_KEY_LEN];
        hdr[0] = OTA_PROTO_VERSION;
        memcpy(hdr + 1, dev_pub, X25519_KEY_LEN);
        if (ssh_send_all(ssh, hdr, sizeof(hdr)) != 0) {
            ESP_LOGE(TAG, "send handshake failed");
            goto out;
        }
    }

    /* ---- 3. Receive client pub ------------------------------------- */
    uint8_t cli_pub[X25519_KEY_LEN];
    if (ssh_read_exact(ssh, cli_pub, X25519_KEY_LEN) != 0) {
        ESP_LOGE(TAG, "client pubkey read failed");
        goto out;
    }

    rc = wc_curve25519_init(&cli_key);
    if (rc != 0) {
        send_failure(ssh, "x25519 init failed");
        goto out;
    }
    cli_key_init = 1;

    rc = wc_curve25519_import_public_ex(cli_pub, X25519_KEY_LEN, &cli_key,
                                        EC25519_LITTLE_ENDIAN);
    if (rc != 0) {
        ESP_LOGE(TAG, "client pubkey import failed: %d", rc);
        send_failure(ssh, "bad client pubkey");
        goto out;
    }

    /* ---- 4. Shared secret + HKDF ----------------------------------- */
    uint8_t shared[X25519_KEY_LEN];
    word32  shared_len = sizeof(shared);
    rc = wc_curve25519_shared_secret_ex(&dev_key, &cli_key, shared, &shared_len,
                                        EC25519_LITTLE_ENDIAN);
    if (rc != 0 || shared_len != X25519_KEY_LEN) {
        ESP_LOGE(TAG, "shared_secret failed: %d", rc);
        send_failure(ssh, "ecdh failed");
        goto out;
    }

    /* info = client_pub || device_pub */
    uint8_t info[X25519_KEY_LEN * 2];
    memcpy(info,                    cli_pub, X25519_KEY_LEN);
    memcpy(info + X25519_KEY_LEN,   dev_pub, X25519_KEY_LEN);

    uint8_t aes_key[OTA_AES_KEY_LEN];
    rc = wc_HKDF(WC_SHA256,
                 shared, shared_len,
                 HKDF_SALT, HKDF_SALT_LEN,
                 info, sizeof(info),
                 aes_key, sizeof(aes_key));
    /* shared is no longer needed; zeroize() is used (not memset) to prevent
     * dead-store elimination by the compiler. */
    zeroize(shared, sizeof(shared));
    if (rc != 0) {
        ESP_LOGE(TAG, "wc_HKDF failed: %d", rc);
        send_failure(ssh, "hkdf failed");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }

    /* ---- 5. Read payload header ------------------------------------ */
    uint8_t  len_buf[4];
    if (ssh_read_exact(ssh, len_buf, 4) != 0) {
        ESP_LOGE(TAG, "payload length read failed");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }
    uint32_t plaintext_len = (uint32_t)len_buf[0]
                           | ((uint32_t)len_buf[1] << 8)
                           | ((uint32_t)len_buf[2] << 16)
                           | ((uint32_t)len_buf[3] << 24);

    if (plaintext_len == 0 || plaintext_len > MAX_OTA_PLAINTEXT) {
        ESP_LOGE(TAG, "bad plaintext_len: %u", (unsigned)plaintext_len);
        send_failure(ssh, "bad plaintext length");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }

    uint8_t iv[OTA_IV_LEN];
    uint8_t tag[OTA_TAG_LEN];
    if (ssh_read_exact(ssh, iv,  OTA_IV_LEN)  != 0 ||
        ssh_read_exact(ssh, tag, OTA_TAG_LEN) != 0) {
        ESP_LOGE(TAG, "iv/tag read failed");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }

    /* ---- 6. Allocate PSRAM ciphertext buffer ----------------------- */
    ciphertext = heap_caps_malloc(plaintext_len, MALLOC_CAP_SPIRAM);
    if (!ciphertext) {
        ESP_LOGE(TAG, "OOM allocating %u bytes in PSRAM",
                 (unsigned)plaintext_len);
        send_failure(ssh, "oom");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }

    if (ssh_read_exact(ssh, ciphertext, plaintext_len) != 0) {
        ESP_LOGE(TAG, "ciphertext read truncated");
        send_failure(ssh, "truncated payload");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }

    /* ---- 7. AES-256-GCM decrypt in place --------------------------- */
    Aes aes;
    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) {
        ESP_LOGE(TAG, "wc_AesInit failed: %d", rc);
        send_failure(ssh, "aes init failed");
        zeroize(aes_key, sizeof(aes_key));
        goto out;
    }
    rc = wc_AesGcmSetKey(&aes, aes_key, OTA_AES_KEY_LEN);
    zeroize(aes_key, sizeof(aes_key));
    if (rc != 0) {
        ESP_LOGE(TAG, "wc_AesGcmSetKey failed: %d", rc);
        wc_AesFree(&aes);
        send_failure(ssh, "aes setkey failed");
        goto out;
    }

    rc = wc_AesGcmDecrypt(&aes,
                          ciphertext, ciphertext, plaintext_len,
                          iv, OTA_IV_LEN,
                          tag, OTA_TAG_LEN,
                          NULL, 0);
    wc_AesFree(&aes);
    if (rc != 0) {
        ESP_LOGE(TAG, "AES-GCM decrypt/verify failed: %d", rc);
        send_failure(ssh, "auth tag verify failed");
        goto out;
    }

    ESP_LOGI(TAG, "Decrypted %u-byte image -- writing to OTA partition",
             (unsigned)plaintext_len);

    /* ---- 8. Stream plaintext to inactive OTA slot ------------------ */
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    if (!next) {
        ESP_LOGE(TAG, "no next OTA partition");
        send_failure(ssh, "no ota partition");
        goto out;
    }

    if (esp_ota_begin(next, plaintext_len, &ota_handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed");
        send_failure(ssh, "ota begin failed");
        goto out;
    }
    ota_began = true;

    const size_t WRITE_CHUNK = 4096;
    for (size_t off = 0; off < plaintext_len; off += WRITE_CHUNK) {
        size_t n = plaintext_len - off;
        if (n > WRITE_CHUNK) n = WRITE_CHUNK;
        if (esp_ota_write(ota_handle, ciphertext + off, n) != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed at offset %u", (unsigned)off);
            send_failure(ssh, "flash write failed");
            goto out;
        }
    }

    if (esp_ota_end(ota_handle) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed");
        /* Do NOT clear ota_began here: the out: label will call
         * esp_ota_abort(ota_handle) to release the OTA partition slot.
         * Clearing ota_began before goto would skip that cleanup and leak
         * the slot, preventing subsequent OTA attempts. */
        send_failure(ssh, "ota end failed");
        goto out;
    }
    ota_began = false;

    if (esp_ota_set_boot_partition(next) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed");
        send_failure(ssh, "set boot partition failed");
        goto out;
    }

    /* ---- 9. Success: 0x00, close, reboot --------------------------- */
    {
        byte ok = 0x00;
        ssh_send_all(ssh, &ok, 1);
    }
    wolfSSH_shutdown(ssh);

    ESP_LOGI(TAG, "OTA image accepted -- rebooting in 2 seconds");
    /* Zero the decrypted plaintext before freeing to prevent it from
     * lingering in PSRAM after the reboot-induced RAM scrub. */
    zeroize(ciphertext, plaintext_len);
    heap_caps_free(ciphertext);
    ciphertext = NULL;
    if (cli_key_init) wc_curve25519_free(&cli_key);
    if (dev_key_init) wc_curve25519_free(&dev_key);
    if (rng_init)     wc_FreeRng(&rng);

    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();
    return ESP_OK; /* unreachable */

out:
    if (ota_began)    esp_ota_abort(ota_handle);
    if (ciphertext) {
        /* Zero decrypted firmware plaintext before releasing PSRAM. */
        zeroize(ciphertext, plaintext_len);
        heap_caps_free(ciphertext);
    }
    if (cli_key_init) wc_curve25519_free(&cli_key);
    if (dev_key_init) wc_curve25519_free(&dev_key);
    if (rng_init)     wc_FreeRng(&rng);
    return ESP_FAIL;
}
