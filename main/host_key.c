/*
 * host_key.c -- ED25519 host key: generate-or-load from NVS
 */

#include "host_key.h"

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "bootloader_random.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/misc.h"
#include "wolfssh/ssh.h"

/* wolfSSL ships ForceZero() as an inlined helper in wolfcrypt/src/misc.c
 * but our build excludes that translation unit.  Map ForceZero to zeroize()
 * which provides the same volatile-write guarantee. */
#define ForceZero(p, n) zeroize((p), (n))

#include "zeroize.h"
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

    int ret = wc_InitSha256(&sha);
    if (ret != 0) {
        ESP_LOGW(TAG, "fingerprint SHA256 failed: %d", ret);
        return;
    }
    ret = wc_Sha256Update(&sha, der, (word32)sz);
    if (ret != 0) {
        ESP_LOGW(TAG, "fingerprint SHA256 failed: %d", ret);
        return;
    }
    ret = wc_Sha256Final(&sha, digest);
    if (ret != 0) {
        ESP_LOGW(TAG, "fingerprint SHA256 failed: %d", ret);
        return;
    }

    /* Print as colon-separated hex, same style as ssh-keygen -l */
    char hex[PUBKEY_HASH_SIZE * 3];
    format_fingerprint(digest, hex, sizeof(hex));
    ESP_LOGI(TAG, "Host key SHA-256 fingerprint: %s", hex);
}

/* ------------------------------------------------------------------ */
/* Key generation                                                      */

/*
 * Entropy gate for first-time ED25519 host-key generation.
 *
 * esp_random() (which wc_InitRng -> wolfCrypt esp32 port reads from) is only
 * cryptographically strong while one of the following is true:
 *   - Wi-Fi or Bluetooth radio is started; OR
 *   - bootloader_random_enable() has been called to seed the RNG from
 *     analog noise sources (SAR ADC + xtal noise).
 *
 * Ref: ESP-IDF docs, "Random Number Generation":
 *   https://docs.espressif.com/projects/esp-idf/en/v6.0.1/esp32s3/api-reference/system/random.html
 * Quote: "When using random number generation API in applications that do not
 *  use Wi-Fi or Bluetooth, the bootloader_random_enable() function can be used
 *  to enable an entropy source ... call bootloader_random_disable() once the
 *  Wi-Fi/Bluetooth driver is initialised, as the analog source can otherwise
 *  affect the operation of analog peripherals."
 *
 * We may be called when Wi-Fi init returned an error (no AP, PSK reject, etc.)
 * so we cannot rely on the radio being up.  We bracket the wc_InitRng /
 * wc_ed25519_make_key / wc_FreeRng sequence with bootloader_random_enable() /
 * _disable() unconditionally when the radio is not in STA-started state.
 * The wrapper is no-op-safe: if Wi-Fi is up the bootloader call is harmless
 * (it just adds a second entropy source for the duration of keygen).
 *
 * Returns 1 if bootloader_random_enable() was called (and the caller must
 * therefore pair it with bootloader_random_disable()); 0 otherwise.
 */
static int entropy_gate_engage(void)
{
    wifi_mode_t mode;
    esp_err_t err = esp_wifi_get_mode(&mode);
    if (err == ESP_OK && (mode == WIFI_MODE_STA || mode == WIFI_MODE_APSTA)) {
        /* Wi-Fi driver initialised -> esp_wifi_start() may have been called;
         * the HW RNG is being seeded by the radio.  Still, the radio may not
         * have associated yet, in which case the seed quality is less than
         * with the analog source.  Call bootloader_random_enable() anyway as
         * a belt-and-braces measure for the brief duration of one keygen --
         * this is safe per ESP-IDF docs as long as we disable it before any
         * SAR/ADC peripheral driver expects clean readings.  Our app does
         * not use SAR-ADC. */
        bootloader_random_enable();
        return 1;
    }
    /* Wi-Fi not initialised at all -- esp_random() output is weak.  Must
     * engage the analog entropy source. */
    bootloader_random_enable();
    ESP_LOGW(TAG, "Wi-Fi not started during host key generation -- "
                  "using bootloader analog entropy source (RNG seed quality OK)");
    return 1;
}

static void entropy_gate_release(int was_engaged)
{
    if (was_engaged) {
        bootloader_random_disable();
    }
}

/*
 * generate_key -- produce a fresh ED25519 keypair into der_out (DER PKCS#8).
 * Shared by both the "load-or-generate-and-persist" main path and the
 * ephemeral fallback when NVS is unwritable.  Caller is responsible for
 * persisting the result.
 */
static esp_err_t generate_key(uint8_t *der_out, size_t *sz_out)
{
    ed25519_key key;
    WC_RNG      rng;
    int         ret;

    /* Gate the RNG init + keygen behind a known-good entropy source.  The
     * generated key is persisted to NVS and never regenerated, so a weak
     * RNG here becomes a permanent device-identity weakness. */
    int gate = entropy_gate_engage();

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        ESP_LOGE(TAG, "wc_InitRng failed: %d", ret);
        entropy_gate_release(gate);
        return ESP_FAIL;
    }

    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        entropy_gate_release(gate);
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
    entropy_gate_release(gate);

    return (ret == 0) ? ESP_OK : ESP_FAIL;
}

static esp_err_t generate_and_save(uint8_t *der_out, size_t *sz_out)
{
    esp_err_t err = generate_key(der_out, sz_out);
    if (err != ESP_OK) return err;

    err = nvs_save_key(der_out, *sz_out);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_save_key failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Generated and stored new ED25519 host key (%zu bytes DER)",
             *sz_out);
    return ESP_OK;
}

/*
 * host_key_generate_ephemeral -- internal fallback for the case where NVS
 * is unwritable at boot.  Generates a fresh key without attempting to
 * persist it.  The key is valid only for the current boot session; on the
 * next reboot a new ephemeral key will be generated (changing the SSH
 * fingerprint each time -- this is intentional: a noisy known_hosts
 * mismatch is the alarm to the operator).
 */
static esp_err_t host_key_generate_ephemeral(uint8_t *der_out, size_t *sz_out)
{
    esp_err_t err = generate_key(der_out, sz_out);
    if (err == ESP_OK) {
        ESP_LOGW(TAG, "Generated EPHEMERAL ED25519 host key (%zu bytes DER) -- "
                       "key will not survive reboot",
                 *sz_out);
    }
    return err;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */

esp_err_t host_key_load_or_generate(WOLFSSH_CTX *ctx)
{
    uint8_t der[KEY_DER_MAX];
    size_t  sz = 0;

    esp_err_t err = nvs_load_key(der, &sz);

    if (err != ESP_OK) {
        /* Treat ANY NVS read failure as "no key on disk" and regenerate.
         *
         * Rationale (audit H3.A): previously we returned err to the caller
         * for any non-NOT_FOUND failure, and the caller wraps the result
         * in ESP_ERROR_CHECK -- so a transient or partition-level NVS error
         * (ESP_ERR_NVS_INVALID_HANDLE / _CORRUPT_KEY_PART / encryption
         * mismatch on a flash that was partially erased / etc.) would panic
         * the device and trap it in a boot loop with no recovery path
         * (usb_cdc_init runs earlier than this so DFU recovery is gone).
         *
         * The safer behaviour: log the actual error code so an operator can
         * detect a corrupted NVS state, then fall through to generate +
         * persist a fresh key.  If the underlying NVS issue is permanent
         * the save will fail in turn and we fall back to an ephemeral key
         * (see generate_and_save handling below).
         *
         * NOT_FOUND is logged at INFO; anything else at WARN since it
         * indicates a state that ideally would not happen. */
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGI(TAG, "No host key in NVS -- generating ...");
        } else {
            ESP_LOGW(TAG, "NVS load error (%s) -- regenerating host key; "
                          "if this persists across reboots, NVS may be "
                          "corrupted (erase + re-provision)",
                     esp_err_to_name(err));
        }

        esp_err_t gen_err = generate_and_save(der, &sz);
        if (gen_err != ESP_OK) {
            /* Persistence failed.  Rather than abort the boot (which would
             * brick the device), fall back to an in-memory-only host key
             * for this boot.  The SSH known_hosts entry will then change on
             * every reboot until NVS works again -- noisy, but the device
             * stays reachable for diagnostics + recovery. */
            ESP_LOGE(TAG, "generate_and_save failed (%s) -- using "
                          "in-memory-only host key for this boot; SSH "
                          "fingerprint will change on next reboot",
                     esp_err_to_name(gen_err));
            sz = 0;
            esp_err_t mem_err = host_key_generate_ephemeral(der, &sz);
            if (mem_err != ESP_OK) {
                /* Even ephemeral keygen failed -- nothing we can do. */
                ForceZero(der, sizeof(der));
                return mem_err;
            }
        }

    } else {
        ESP_LOGI(TAG, "Loaded ED25519 host key from NVS (%zu bytes)", sz);
        /* Defence-in-depth advisory: pre-fix firmware (HEAD<=00746ec) may
         * have generated this key from an unseeded esp_random() if the radio
         * was not yet up.  The on-disk format is unchanged so we cannot
         * distinguish a weak key from a strong one; surface the fingerprint
         * + advisory on every boot so an operator can rotate if they suspect
         * the device shipped before the entropy fix landed.  Auto-rotation
         * would invalidate known_hosts entries deployed in the field. */
        ESP_LOGW(TAG, "If this device was first provisioned with firmware "
                       "before the entropy-gate fix, consider rotating the SSH "
                       "host key (erase NVS namespace \"ssh\" key \""
                       NVS_KEY_HOST "\").  Fingerprint follows:");
    }

    log_fingerprint(der, sz);

    int wsret = wolfSSH_CTX_UsePrivateKey_buffer(
        ctx, der, (word32)sz, WOLFSSH_FORMAT_ASN1);

    ForceZero(der, sizeof(der));

    if (wsret < 0) {
        ESP_LOGE(TAG, "wolfSSH_CTX_UsePrivateKey_buffer failed: %d", wsret);
        return ESP_FAIL;
    }
    return ESP_OK;
}
