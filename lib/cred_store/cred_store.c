/*
 * cred_store.c -- NVS-backed SCEP credential store implementation
 *
 * The NVS backend is compiled out when CRED_STORE_NATIVE_TEST is defined.
 * In that mode a simple in-memory backend is used, allowing the pure parsing
 * logic (cred_store_parse_not_after, cred_store_parse_not_before) to be tested
 * natively without ESP-IDF NVS.
 *
 * Key material is wiped with zeroize() on every exit path.
 *
 * mbedTLS API used for date extraction:
 *   mbedtls_x509_crt_parse_der -- one-shot DER parse
 *   crt.valid_to              -- mbedtls_x509_time { year, mon, day, hour, min, sec }
 *   crt.valid_from            -- same struct, for NotBefore
 */

#include "cred_store.h"
#include "zeroize.h"

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "esp_log.h"

static const char *TAG = "cred_store";

/* mbedTLS X.509 -- same headers work for the on-device build and the
 * native-test build (system libmbedtls). */
#include "mbedtls/x509_crt.h"

/* --------------------------------------------------------------------------
 * x509_time_to_epoch -- shared Howard Hinnant date-to-epoch helper
 *
 * timegm() is glibc/BSD-specific; ESP-IDF's newlib does not provide it.
 * This computes the UTC epoch directly from an mbedtls_x509_time so both
 * cred_store_parse_not_after and cred_store_parse_not_before share the same
 * arithmetic without duplication.
 *
 * Howard Hinnant's date-to-epoch algorithm:
 *   https://howardhinnant.github.io/date_algorithms.html#days_from_civil
 * -------------------------------------------------------------------------- */

static esp_err_t x509_time_to_epoch(const mbedtls_x509_time *xt,
                                    uint64_t                 *out_epoch)
{
    int y = xt->year;
    int m = xt->mon;
    int d = xt->day;
    y -= (m <= 2);
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);                        /* 0..399 */
    unsigned doy = (153U * (unsigned)(m > 2 ? m - 3 : m + 9) + 2U) / 5U
                   + (unsigned)d - 1U;                               /* 0..365 */
    unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;         /* 0..146096 */
    int64_t days = (int64_t)era * 146097LL + (int64_t)doe - 719468LL; /* days since 1970-01-01 */
    int64_t epoch = days * 86400LL
                  + (int64_t)xt->hour * 3600LL
                  + (int64_t)xt->min  * 60LL
                  + (int64_t)xt->sec;

    /* Reject implausibly small results (pre-2024) to catch conversion errors.
     * MIN_PLAUSIBLE_EPOCH ~ 1.7e9 (year 2024); use a slightly earlier floor
     * so certs issued in 2023 are still accepted. */
#define MIN_PLAUSIBLE_EPOCH_CRED  INT64_C(1700000000)   /* ~Nov 2023 */
    if (epoch < MIN_PLAUSIBLE_EPOCH_CRED) {
        return ESP_FAIL;
    }
#undef MIN_PLAUSIBLE_EPOCH_CRED

    *out_epoch = (uint64_t)epoch;
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * parse_x509_time -- shared implementation for not_after / not_before
 *
 * use_not_before=false reads crt.valid_to (NotAfter).
 * use_not_before=true  reads crt.valid_from (NotBefore).
 * -------------------------------------------------------------------------- */
static esp_err_t parse_x509_time(const uint8_t *cert_der,
                                  size_t         cert_len,
                                  bool           use_not_before,
                                  uint64_t      *out)
{
    if (!cert_der || cert_len == 0 || !out) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, cert_der, cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse_der failed: -0x%04x",
                 (unsigned)(-ret));
        mbedtls_x509_crt_free(&crt);
        return ESP_FAIL;
    }

    const mbedtls_x509_time *xt = use_not_before ? &crt.valid_from : &crt.valid_to;
    esp_err_t err = x509_time_to_epoch(xt, out);
    mbedtls_x509_crt_free(&crt);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "epoch conversion failed for %s",
                 use_not_before ? "NotBefore" : "NotAfter");
    }
    return err;
}

/* --------------------------------------------------------------------------
 * cred_store_parse_not_after -- pure function, native-testable
 * -------------------------------------------------------------------------- */

esp_err_t cred_store_parse_not_after(const uint8_t *cert_der,
                                     size_t         cert_len,
                                     uint64_t      *out_epoch)
{
    return parse_x509_time(cert_der, cert_len, false, out_epoch);
}

/* --------------------------------------------------------------------------
 * cred_store_parse_not_before -- pure function, native-testable
 *
 * Reads crt.valid_from (X.509 NotBefore field) and converts to epoch seconds.
 * Used by the no-NTP boot mode to set the local clock from the CA-issued cert.
 * -------------------------------------------------------------------------- */

esp_err_t cred_store_parse_not_before(const uint8_t *cert_der,
                                      size_t         cert_len,
                                      uint64_t      *out_epoch)
{
    return parse_x509_time(cert_der, cert_len, true, out_epoch);
}

/* ==========================================================================
 * NVS backend (real ESP-IDF device build)
 * ========================================================================== */

#ifndef CRED_STORE_NATIVE_TEST

#include "nvs.h"
#include "nvs_flash.h"

#define CRED_NVS_NS          "creds"
#define CRED_KEY_DEV_KEY     "dev_key"
#define CRED_KEY_DEV_CERT    "dev_cert"
#define CRED_KEY_CA_CHAIN    "ca_chain"
#define CRED_KEY_NOT_AFTER   "not_after"

esp_err_t cred_store_load(cred_store_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    nvs_handle_t h;
    esp_err_t err = nvs_open(CRED_NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        /* Namespace doesn't exist yet -> not yet enrolled. */
        ESP_LOGD(TAG, "nvs_open(\"%s\") failed: %s -- not enrolled",
                 CRED_NVS_NS, esp_err_to_name(err));
        return ESP_ERR_NVS_NOT_FOUND;
    }

    out->dev_key_len = CRED_DEV_KEY_MAX;
    err = nvs_get_blob(h, CRED_KEY_DEV_KEY, out->dev_key, &out->dev_key_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "dev_key not found: %s", esp_err_to_name(err));
        goto not_found;
    }

    out->dev_cert_len = CRED_DEV_CERT_MAX;
    err = nvs_get_blob(h, CRED_KEY_DEV_CERT, out->dev_cert, &out->dev_cert_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "dev_cert not found: %s", esp_err_to_name(err));
        goto not_found;
    }

    out->ca_chain_len = CRED_CA_CHAIN_MAX;
    err = nvs_get_blob(h, CRED_KEY_CA_CHAIN, out->ca_chain, &out->ca_chain_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "ca_chain not found: %s", esp_err_to_name(err));
        goto not_found;
    }

    err = nvs_get_u64(h, CRED_KEY_NOT_AFTER, &out->not_after);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "not_after not found: %s", esp_err_to_name(err));
        goto not_found;
    }

    nvs_close(h);
    ESP_LOGI(TAG, "Credentials loaded (cert %zu B, key %zu B, not_after %llu)",
             out->dev_cert_len, out->dev_key_len,
             (unsigned long long)out->not_after);
    return ESP_OK;

not_found:
    nvs_close(h);
    zeroize(out, sizeof(*out));
    return ESP_ERR_NVS_NOT_FOUND;
}

esp_err_t cred_store_save(const cred_store_t *in)
{
    if (!in) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = nvs_open(CRED_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open rw failed: %s", esp_err_to_name(err));
        return err;
    }

#define SET_BLOB(key, ptr, len) do { \
    err = nvs_set_blob(h, (key), (ptr), (len)); \
    if (err != ESP_OK) { ESP_LOGE(TAG, "nvs_set_blob(%s): %s", (key), esp_err_to_name(err)); goto save_fail; } \
} while(0)

    SET_BLOB(CRED_KEY_DEV_KEY,  in->dev_key,  in->dev_key_len);
    SET_BLOB(CRED_KEY_DEV_CERT, in->dev_cert, in->dev_cert_len);
    SET_BLOB(CRED_KEY_CA_CHAIN, in->ca_chain, in->ca_chain_len);

    err = nvs_set_u64(h, CRED_KEY_NOT_AFTER, in->not_after);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_u64(not_after): %s", esp_err_to_name(err));
        goto save_fail;
    }

    /* nvs_commit() is atomic at the flash-page level: all four keys above are
     * in the NVS write cache and become durable together in a single page
     * write.  A power loss before nvs_commit() leaves the flash unchanged
     * (prior credentials, if any, remain intact).  A power loss *after*
     * nvs_commit() completes atomically persists all four keys or none.
     * There is no window where the device can boot with a partially-written
     * credential set from this call. */
    err = nvs_commit(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_commit failed: %s", esp_err_to_name(err));
        goto save_fail;
    }

    nvs_close(h);
    ESP_LOGI(TAG, "Credentials saved (cert %zu B, key %zu B, not_after %llu)",
             in->dev_cert_len, in->dev_key_len,
             (unsigned long long)in->not_after);
    return ESP_OK;

#undef SET_BLOB

save_fail:
    nvs_close(h);
    return err;
}

esp_err_t cred_store_clear(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(CRED_NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;   /* nothing to clear */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open for clear: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_erase_all(h);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);

    if (err != ESP_OK)
        ESP_LOGE(TAG, "cred_store_clear failed: %s", esp_err_to_name(err));
    else
        ESP_LOGI(TAG, "Credential store cleared");
    return err;
}

#else /* CRED_STORE_NATIVE_TEST -- in-memory backend */

/* ==========================================================================
 * In-memory backend for native unit tests.
 *
 * A single static cred_store_t holds the "stored" credentials.
 * s_mem_present tracks whether a save() has been called.
 * ========================================================================== */

static cred_store_t s_mem_store;
static int          s_mem_present = 0;

esp_err_t cred_store_load(cred_store_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    if (!s_mem_present) return ESP_ERR_NVS_NOT_FOUND;
    memcpy(out, &s_mem_store, sizeof(*out));
    return ESP_OK;
}

esp_err_t cred_store_save(const cred_store_t *in)
{
    if (!in) return ESP_ERR_INVALID_ARG;
    memcpy(&s_mem_store, in, sizeof(s_mem_store));
    s_mem_present = 1;
    return ESP_OK;
}

esp_err_t cred_store_clear(void)
{
    zeroize(&s_mem_store, sizeof(s_mem_store));
    s_mem_present = 0;
    return ESP_OK;
}

#endif /* CRED_STORE_NATIVE_TEST */
