/*
 * host_key.c — ED25519 host key: generate-or-load from NVS
 */

#include "host_key.h"

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssh/ssh.h"

#include "pubkey_auth.h"

static const char *TAG = "host_key";

#define NVS_NAMESPACE   "ssh"
#define NVS_KEY_HOST    "host_ed25519"

/* ED25519 DER private key is ~83 bytes; 128 gives comfortable headroom. */
#define KEY_DER_MAX     128

/* ------------------------------------------------------------------ */
/* NVS helpers                                                         */

static esp_err_t nvs_load_key(uint8_t *der_out, size_t *sz_out)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) return err;

    size_t len = KEY_DER_MAX;
    err = nvs_get_blob(h, NVS_KEY_HOST, der_out, &len);
    if (err == ESP_OK) *sz_out = len;
    nvs_close(h);
    return err;
}

static esp_err_t nvs_save_key(const uint8_t *der, size_t sz)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    err = nvs_set_blob(h, NVS_KEY_HOST, der, sz);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

/* ------------------------------------------------------------------ */
/* Fingerprint: SHA-256 over the DER bytes, printed as hex             */

static void log_fingerprint(const uint8_t *der, size_t sz)
{
    Sha256  sha;
    uint8_t digest[PUBKEY_HASH_SIZE];

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, der, (word32)sz);
    wc_Sha256Final(&sha, digest);

    /* Print as colon-separated hex, same style as ssh-keygen -l */
    char hex[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, hex, sizeof(hex));
    ESP_LOGI(TAG, "Host key SHA-256 fingerprint: %s", hex);
}

/* ------------------------------------------------------------------ */
/* Key generation                                                      */

static esp_err_t generate_and_save(uint8_t *der_out, size_t *sz_out)
{
    ed25519_key key;
    WC_RNG      rng;
    int         ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        ESP_LOGE(TAG, "wc_InitRng failed: %d", ret);
        return ESP_FAIL;
    }

    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        ESP_LOGE(TAG, "wc_ed25519_init failed: %d", ret);
        return ESP_FAIL;
    }

    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
    if (ret != 0) {
        ESP_LOGE(TAG, "wc_ed25519_make_key failed: %d", ret);
        goto out;
    }

    word32 der_sz = KEY_DER_MAX;
    ret = wc_Ed25519KeyToDer(&key, der_out, der_sz);
    if (ret < 0) {
        ESP_LOGE(TAG, "wc_Ed25519KeyToDer failed: %d", ret);
        goto out;
    }
    *sz_out = (size_t)ret;
    ret = 0;

out:
    wc_ed25519_free(&key);
    wc_FreeRng(&rng);

    if (ret != 0) return ESP_FAIL;

    esp_err_t err = nvs_save_key(der_out, *sz_out);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_save_key failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Generated and stored new ED25519 host key (%zu bytes DER)",
             *sz_out);
    return ESP_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */

esp_err_t host_key_load_or_generate(WOLFSSH_CTX *ctx)
{
    uint8_t der[KEY_DER_MAX];
    size_t  sz = 0;

    esp_err_t err = nvs_load_key(der, &sz);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No host key in NVS — generating …");
        err = generate_and_save(der, &sz);
        if (err != ESP_OK) return err;

    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS load error: %s", esp_err_to_name(err));
        return err;
    } else {
        ESP_LOGI(TAG, "Loaded ED25519 host key from NVS (%zu bytes)", sz);
    }

    log_fingerprint(der, sz);

    int wsret = wolfSSH_CTX_UsePrivateKey_buffer(
        ctx, der, (word32)sz, WOLFSSH_FORMAT_ASN1);

    memset(der, 0, sizeof(der));  /* wipe from stack */

    if (wsret < 0) {
        ESP_LOGE(TAG, "wolfSSH_CTX_UsePrivateKey_buffer failed: %d", wsret);
        return ESP_FAIL;
    }
    return ESP_OK;
}
