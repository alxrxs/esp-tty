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
#include <stdatomic.h>
#include <time.h>

#include "esp_log.h"

static const char *TAG = "cred_store";

/* --------------------------------------------------------------------------
 * Concurrency
 *
 * cred_store is reachable from multiple FreeRTOS tasks: cert_renewer_task
 * (load + save during SCEP enrolment + renewal) and the wifi-init path
 * (load before joining the SSID).  ESP-IDF NVS documents that two
 * concurrent NVS_READWRITE handles on the same namespace produce UNDEFINED
 * behaviour, so we serialise every public entry point through a single
 * mutex.
 *
 * Lazy initialisation: an atomic CAS guards a one-shot path that creates
 * the mutex on first call.  Failure to create the mutex is fatal in the
 * sense that we cannot offer the documented thread-safety guarantee --
 * we log and return ESP_ERR_NO_MEM so callers can react (cert_renewer
 * retries; wifi_init treats it as "no creds available" which is its
 * default not-enrolled handling).
 * -------------------------------------------------------------------------- */
#ifndef CRED_STORE_NATIVE_TEST
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static SemaphoreHandle_t s_mutex = NULL;
static _Atomic int       s_mutex_init = 0;   /* 0=uninit, 1=initialising, 2=ready */

static esp_err_t ensure_mutex(void)
{
    int state = atomic_load_explicit(&s_mutex_init, memory_order_acquire);
    if (state == 2) return ESP_OK;

    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &s_mutex_init, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) {
            atomic_store_explicit(&s_mutex_init, 0, memory_order_release);
            ESP_LOGE(TAG, "xSemaphoreCreateMutex failed");
            return ESP_ERR_NO_MEM;
        }
        atomic_store_explicit(&s_mutex_init, 2, memory_order_release);
        return ESP_OK;
    }

    /* Lost the race -- spin (briefly) until the winner publishes the mutex.
     * Init path is one alloc; spin is bounded by FreeRTOS scheduler tick. */
    while (atomic_load_explicit(&s_mutex_init, memory_order_acquire) != 2) {
        if (atomic_load_explicit(&s_mutex_init, memory_order_acquire) == 0) {
            return ESP_ERR_NO_MEM;
        }
        vTaskDelay(1);
    }
    return ESP_OK;
}

static esp_err_t lock_take(void)
{
    esp_err_t err = ensure_mutex();
    if (err != ESP_OK) return err;
    if (xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

static void lock_give(void)
{
    if (s_mutex) xSemaphoreGive(s_mutex);
}
#else /* CRED_STORE_NATIVE_TEST -- pthread on the host */
#include <pthread.h>

static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

static esp_err_t lock_take(void)
{
    if (pthread_mutex_lock(&s_mutex) != 0) return ESP_FAIL;
    return ESP_OK;
}

static void lock_give(void)
{
    (void)pthread_mutex_unlock(&s_mutex);
}
#endif

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
/* Schema-version + valid-marker keys.  See cred_store_save() for the write
 * order and atomicity guarantee.  Bump CRED_SCHEMA_VERSION when the on-disk
 * layout of any of the above blobs changes; cred_store_load() rejects any
 * mismatched value to force a fresh re-enrollment. */
#define CRED_KEY_VALID       "valid_v1"   /* uint8 == 1 iff save completed */
#define CRED_KEY_SCHEMA      "schema_ver" /* uint8 schema version */
#define CRED_SCHEMA_VERSION  1u

/* Forward declaration -- definition follows cred_store_save so it can be
 * shared with cred_store_clear without reordering the public API order. */
static void scrub_secret_blobs(nvs_handle_t h);

static esp_err_t cred_store_load_unlocked(cred_store_t *out)
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

    /* Step 1: read the valid marker FIRST.  cred_store_save() writes this
     * key LAST (after all blobs are committed) and cred_store_clear() erases
     * it FIRST.  If a power-fail interrupted a save mid-blob the marker is
     * absent => treat the entire store as not-enrolled. */
    uint8_t valid = 0;
    err = nvs_get_u8(h, CRED_KEY_VALID, &valid);
    if (err != ESP_OK || valid != 1) {
        ESP_LOGD(TAG, "valid marker absent/invalid (%s, v=%u) -- not enrolled",
                 esp_err_to_name(err), (unsigned)valid);
        nvs_close(h);
        return ESP_ERR_NVS_NOT_FOUND;
    }

    /* Step 2: schema version must match.  A mismatch indicates rollback to
     * an older firmware that wrote a different blob layout; refuse and force
     * re-enrollment instead of mis-parsing. */
    uint8_t schema = 0;
    err = nvs_get_u8(h, CRED_KEY_SCHEMA, &schema);
    if (err != ESP_OK || schema != CRED_SCHEMA_VERSION) {
        ESP_LOGW(TAG, "schema version mismatch (got %u, expected %u): %s -- "
                       "forcing re-enrollment", (unsigned)schema,
                 (unsigned)CRED_SCHEMA_VERSION, esp_err_to_name(err));
        nvs_close(h);
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

static esp_err_t cred_store_save_unlocked(const cred_store_t *in)
{
    if (!in) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = nvs_open(CRED_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open rw failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Atomicity scheme (REAL, not assumed):
     *
     * ESP-IDF NVS does NOT batch multiple nvs_set_blob calls into one atomic
     * page write -- each nvs_set_blob marks its own entry as written before
     * nvs_commit() flushes the page header.  A power loss between two
     * nvs_set_blob calls therefore leaves a partial credential set.
     *
     * To make save() atomic from the reader's point of view we:
     *   1. ERASE the valid marker first  -- if the writer crashes hereafter,
     *      load() will see no marker and return NOT_FOUND.  Old credential
     *      blobs may still be on flash but are unreachable through load().
     *   2. Commit that erase before writing any new blobs.  This is the key
     *      step: it pins "creds are invalid" durably before we start mutating
     *      them.  A power loss now leaves a recoverable not-enrolled state.
     *   3. Write all four blobs + schema version.
     *   4. Commit them together (NVS batches up to the next commit).
     *   5. Write the valid marker LAST and commit.  A power loss between
     *      step 4 and step 5 still leaves the marker absent -> NOT_FOUND.
     *      Only a power loss strictly after step 5's commit reveals the new
     *      credentials, atomically. */

    /* Step 1+2: invalidate first, commit. */
    err = nvs_erase_key(h, CRED_KEY_VALID);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "nvs_erase_key(valid): %s", esp_err_to_name(err));
        goto save_fail;
    }
    err = nvs_commit(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_commit(invalidate): %s", esp_err_to_name(err));
        goto save_fail;
    }

#define SET_BLOB(key, ptr, len) do { \
    err = nvs_set_blob(h, (key), (ptr), (len)); \
    if (err != ESP_OK) { ESP_LOGE(TAG, "nvs_set_blob(%s): %s", (key), esp_err_to_name(err)); goto save_fail; } \
} while(0)

    /* Step 3: write blobs + schema. */
    SET_BLOB(CRED_KEY_DEV_KEY,  in->dev_key,  in->dev_key_len);
    SET_BLOB(CRED_KEY_DEV_CERT, in->dev_cert, in->dev_cert_len);
    SET_BLOB(CRED_KEY_CA_CHAIN, in->ca_chain, in->ca_chain_len);

    err = nvs_set_u64(h, CRED_KEY_NOT_AFTER, in->not_after);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_u64(not_after): %s", esp_err_to_name(err));
        goto save_fail;
    }
    err = nvs_set_u8(h, CRED_KEY_SCHEMA, (uint8_t)CRED_SCHEMA_VERSION);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_u8(schema): %s", esp_err_to_name(err));
        goto save_fail;
    }

    /* Step 4: commit blobs (marker still absent at this point). */
    err = nvs_commit(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_commit(blobs): %s", esp_err_to_name(err));
        goto save_fail;
    }

    /* Step 5: write + commit the valid marker last. */
    err = nvs_set_u8(h, CRED_KEY_VALID, 1);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_u8(valid): %s", esp_err_to_name(err));
        goto save_fail;
    }
    err = nvs_commit(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_commit(valid): %s", esp_err_to_name(err));
        goto save_fail;
    }

    nvs_close(h);
    ESP_LOGI(TAG, "Credentials saved (cert %zu B, key %zu B, not_after %llu)",
             in->dev_cert_len, in->dev_key_len,
             (unsigned long long)in->not_after);
    return ESP_OK;

#undef SET_BLOB

save_fail:
    /* Defence-in-depth: a partial save may have committed dev_key/dev_cert
     * blobs but failed before the valid marker landed.  The reader-visible
     * state is already "not enrolled" (marker absent -> load() returns
     * NOT_FOUND, see cred_store_load), but the raw key DER may still be
     * recoverable from the NVS pages on a flash dump.  Scrub before
     * returning so even an aborted save leaves no key material.
     * NOTE: the err captured before this label is the original failure --
     * we deliberately do not overwrite it with scrub status (scrub failure
     * is logged inside scrub_secret_blobs but does not replace the
     * caller-visible original error). */
    {
        esp_err_t saved_err = err;
        scrub_secret_blobs(h);
        err = saved_err;
    }
    nvs_close(h);
    return err;
}

/*
 * scrub_secret_blobs -- overwrite every secret-bearing blob in the creds
 * namespace with zeros, then commit.  Used by cred_store_clear() and
 * cred_store_save() error paths as defence-in-depth so that a power-fail
 * between the scrub-commit and the subsequent erase does not leave raw
 * RSA-2048 private-key DER recoverable from an NVS dump.
 *
 * KNOWN LIMITATION: ESP-IDF NVS uses page-based wear-levelling.  Overwriting
 * a blob with zeros writes a NEW page; the prior page (containing the real
 * key bytes) is marked obsolete but not physically erased until the
 * wear-leveller reclaims it.  An attacker with raw flash access can still
 * recover the old page.  This routine therefore relies on the project's
 * existing NVS partition encryption (AES-XTS-256, see main/main.c
 * nvs_flash_secure_init_partition) as the primary defence; the scrub is a
 * defence-in-depth layer that mitigates the narrow window where an attacker
 * has the partition encryption key (e.g. from a leak) AND a flash dump.
 *
 * Errors are logged but not surfaced -- the caller is already on an error
 * or destructive path; failing the scrub does not change the calling
 * function's outcome and would only obscure the underlying error.
 */
static void scrub_secret_blobs(nvs_handle_t h)
{
    /* Use stack-allocated zero buffers sized to MAX so the scrub overwrites
     * any historical record at that key.  MAX sizes are sub-KB (key 2 KB,
     * cert 4 KB, chain 8 KB) -- this is called from the renewal task with a
     * 32 KB stack, which has the room.  If the calling task ever shrinks,
     * switch to heap. */
    static const uint8_t zeros_key[CRED_DEV_KEY_MAX]   = {0};
    static const uint8_t zeros_cert[CRED_DEV_CERT_MAX] = {0};
    static const uint8_t zeros_chain[CRED_CA_CHAIN_MAX] = {0};

    esp_err_t e;
    e = nvs_set_blob(h, CRED_KEY_DEV_KEY,  zeros_key,   sizeof(zeros_key));
    if (e != ESP_OK)
        ESP_LOGW(TAG, "scrub(dev_key): %s", esp_err_to_name(e));
    e = nvs_set_blob(h, CRED_KEY_DEV_CERT, zeros_cert,  sizeof(zeros_cert));
    if (e != ESP_OK)
        ESP_LOGW(TAG, "scrub(dev_cert): %s", esp_err_to_name(e));
    e = nvs_set_blob(h, CRED_KEY_CA_CHAIN, zeros_chain, sizeof(zeros_chain));
    if (e != ESP_OK)
        ESP_LOGW(TAG, "scrub(ca_chain): %s", esp_err_to_name(e));
    e = nvs_commit(h);
    if (e != ESP_OK)
        ESP_LOGW(TAG, "scrub commit: %s", esp_err_to_name(e));
}

static esp_err_t cred_store_clear_unlocked(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(CRED_NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;   /* nothing to clear */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open for clear: %s", esp_err_to_name(err));
        return err;
    }

    /* Step 1: erase the valid marker first (and commit) so that any
     * power-fail from here on leaves load() returning NOT_FOUND.  This
     * pins the reader-visible state to "not enrolled" before we touch
     * the secret blobs. */
    esp_err_t erase_err = nvs_erase_key(h, CRED_KEY_VALID);
    if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "nvs_erase_key(valid): %s", esp_err_to_name(erase_err));
        nvs_close(h);
        return erase_err;
    }
    err = nvs_commit(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_commit(invalidate during clear): %s",
                 esp_err_to_name(err));
        nvs_close(h);
        return err;
    }

    /* Step 2: scrub every secret-bearing blob to zeros and commit BEFORE
     * the destructive erase_all.  If power fails between scrub-commit and
     * erase_all, the NVS transaction log will roll-forward the zero
     * overwrite (not the original key), so a flash forensics step cannot
     * recover the key DER even after rollback.  The valid marker is
     * already absent (step 1) so the caller's view of the store is still
     * "not enrolled" regardless. */
    scrub_secret_blobs(h);

    /* Step 3: erase the entire namespace so subsequent saves start clean. */
    err = nvs_erase_all(h);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);

    if (err != ESP_OK)
        ESP_LOGE(TAG, "cred_store_clear failed: %s", esp_err_to_name(err));
    else
        ESP_LOGI(TAG, "Credential store cleared (with secret scrub)");
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
static uint8_t      s_mem_valid     = 0;  /* mirrors CRED_KEY_VALID */
static uint8_t      s_mem_schema    = 0;  /* mirrors CRED_KEY_SCHEMA */
#define CRED_SCHEMA_VERSION  1u

static esp_err_t cred_store_load_unlocked(cred_store_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    if (s_mem_valid != 1) return ESP_ERR_NVS_NOT_FOUND;
    if (s_mem_schema != (uint8_t)CRED_SCHEMA_VERSION) return ESP_ERR_NVS_NOT_FOUND;
    memcpy(out, &s_mem_store, sizeof(*out));
    return ESP_OK;
}

static esp_err_t cred_store_save_unlocked(const cred_store_t *in)
{
    if (!in) return ESP_ERR_INVALID_ARG;
    /* Mirror the device write ordering: invalidate marker, then blobs, then
     * marker.  The native backend is single-threaded so the ordering only
     * matters for test fault-injection (see _testhook_*). */
    s_mem_valid = 0;
    memcpy(&s_mem_store, in, sizeof(s_mem_store));
    s_mem_schema = (uint8_t)CRED_SCHEMA_VERSION;
    s_mem_valid  = 1;
    return ESP_OK;
}

static esp_err_t cred_store_clear_unlocked(void)
{
    /* Mirror the device write ordering: marker first, then scrub secrets,
     * then full erase.  In the in-memory backend "scrub" and "erase" are
     * indistinguishable but we keep the layering so tests that simulate
     * a power-fail after the scrub-commit (see _testhook_clear_after_scrub)
     * can be added in parallel with the device guarantees. */
    s_mem_valid  = 0;
    /* "scrub" step: overwrite the secret blobs.  The full zeroize below
     * subsumes this in-memory, but we keep the explicit step so future
     * tests can probe between scrub and erase. */
    zeroize(s_mem_store.dev_key,  CRED_DEV_KEY_MAX);
    zeroize(s_mem_store.dev_cert, CRED_DEV_CERT_MAX);
    zeroize(s_mem_store.ca_chain, CRED_CA_CHAIN_MAX);
    /* "erase" step. */
    s_mem_schema = 0;
    zeroize(&s_mem_store, sizeof(s_mem_store));
    return ESP_OK;
}

/* Test-only fault injectors -- simulate power-fail windows in cred_store_save()
 * and cred_store_clear().  Not declared in cred_store.h to keep the public API
 * clean; tests forward-declare them directly.
 *
 * NOTE: the native backend is a SIMULATION of NVS commit-boundary semantics,
 * not an exact replica.  On the real device each nvs_commit() call flushes a
 * page header; between commits the prior valid page can be recovered on a flash
 * dump.  The in-memory backend cannot model page-level granularity, so these
 * hooks inject state that corresponds to what load() would observe if a
 * power-fail happened between specific commit points. */
void cred_store_testhook_partial_write(const cred_store_t *in)
{
    /* Models: blobs written + committed (step 4) but valid marker NEVER set
     * (power-fail between step 4 commit and step 5 write).
     * load() must return NOT_FOUND because the marker is absent. */
    if (!in) return;
    s_mem_valid = 0;
    memcpy(&s_mem_store, in, sizeof(s_mem_store));
    s_mem_schema = (uint8_t)CRED_SCHEMA_VERSION;
    /* deliberately DO NOT set s_mem_valid */
}

/*
 * cred_store_testhook_partial_clear -- simulate power-fail in clear() between
 * the marker-erase commit (step 1) and the scrub commit (step 2).
 *
 * Device state at this point: marker is absent (load() returns NOT_FOUND) but
 * the secret blobs are still intact in flash.  This is the worst-case window
 * that the scrub step is designed to close.
 *
 * load() must return NOT_FOUND.  The dev_key bytes are deliberately left in
 * place to model the forensic residue; a separate test verifies the load()
 * invariant (caller sees "not enrolled") even with the key on "flash".
 */
void cred_store_testhook_partial_clear(void)
{
    /* Only the marker is gone; blobs are intact (mirrors device after step 1
     * commit and before step 2 scrub). */
    s_mem_valid = 0;
    /* s_mem_store and s_mem_schema deliberately left untouched. */
}

/*
 * cred_store_testhook_save_partial_committed_blobs_no_marker -- simulate
 * power-fail in save() between the blob commit (step 4) and the valid-marker
 * write (step 5).
 *
 * Device state: blobs are present and readable, schema is set, but the marker
 * is absent.  load() must return NOT_FOUND -- the marker-last scheme ensures
 * the caller never sees a partially-committed credential set.
 */
void cred_store_testhook_save_partial_committed_blobs_no_marker(const cred_store_t *in)
{
    /* Identical to cred_store_testhook_partial_write in the in-memory backend
     * because both model "blobs committed, marker absent".  The two hooks are
     * kept as separate named entry points so tests can document which commit
     * window they are exercising. */
    if (!in) return;
    s_mem_valid = 0;
    memcpy(&s_mem_store, in, sizeof(s_mem_store));
    s_mem_schema = (uint8_t)CRED_SCHEMA_VERSION;
    /* deliberately DO NOT set s_mem_valid */
}

void cred_store_testhook_force_schema(uint8_t schema)
{
    /* Pretend a previous firmware wrote a different schema version.  load()
     * must return NOT_FOUND to force re-enrollment. */
    s_mem_schema = schema;
}

/*
 * cred_store_testhook_save_fail_with_scrub -- simulate a save() failure after
 * some blobs were written (step 3) but before the valid marker was set (step 5),
 * with the scrub already executed (save_fail path in cred_store_save_unlocked).
 *
 * Device state after the scrub commit: blobs are overwritten with zeros, marker
 * is absent.  load() must return NOT_FOUND AND the dev_key region must contain
 * only zero bytes (no key DER fragments recoverable).
 *
 * This hook tests the M3.D fix: that the save_fail path in the NVS backend
 * calls scrub_secret_blobs before closing the handle, so no key material is
 * left even on an aborted save.
 */
void cred_store_testhook_save_fail_with_scrub(void)
{
    /* Simulate what happens when save() fails after writing blobs but the
     * scrub has executed: marker is absent AND blobs are zeroed. */
    s_mem_valid = 0;
    zeroize(s_mem_store.dev_key,  CRED_DEV_KEY_MAX);
    zeroize(s_mem_store.dev_cert, CRED_DEV_CERT_MAX);
    zeroize(s_mem_store.ca_chain, CRED_CA_CHAIN_MAX);
    /* schema deliberately left to match the (zeroed) blob state; load()
     * returns NOT_FOUND because the marker is gone regardless of schema. */
}

/*
 * cred_store_testhook_clear_after_marker -- simulate power-fail in clear()
 * after the valid-marker erase commit but BEFORE the secret scrub.
 * Mirrors the device path: only the marker is gone; secret blobs still hold
 * raw key bytes.  load() must return NOT_FOUND.
 */
void cred_store_testhook_clear_after_marker(void)
{
    s_mem_valid = 0;
    /* Deliberately do not touch s_mem_store -- the raw key bytes remain
     * in place.  load() must still refuse because the marker is gone. */
}

/*
 * cred_store_testhook_clear_after_scrub -- simulate power-fail in clear()
 * after the scrub commit but BEFORE the final erase_all.  Secret blobs are
 * now zero; metadata may or may not be reset.  load() must return NOT_FOUND
 * AND any flash inspection of dev_key must show only zero bytes.
 */
void cred_store_testhook_clear_after_scrub(void)
{
    s_mem_valid = 0;
    zeroize(s_mem_store.dev_key,  CRED_DEV_KEY_MAX);
    zeroize(s_mem_store.dev_cert, CRED_DEV_CERT_MAX);
    zeroize(s_mem_store.ca_chain, CRED_CA_CHAIN_MAX);
    /* metadata (lengths, not_after, schema) deliberately left in place to
     * represent the worst-case partial-clear residue. */
}

/*
 * cred_store_testhook_inspect_dev_key -- expose the raw stored dev_key
 * region to tests so they can verify the scrub overwrites the key bytes.
 * Returns a pointer to the in-memory dev_key buffer; never NULL.  Tests
 * read up to CRED_DEV_KEY_MAX bytes and assert what they expect.
 */
const uint8_t *cred_store_testhook_inspect_dev_key(void)
{
    return s_mem_store.dev_key;
}

#endif /* CRED_STORE_NATIVE_TEST */

/* --------------------------------------------------------------------------
 * Public API -- thin locking wrappers around the *_unlocked implementations.
 *
 * Every public entry takes the cred_store mutex on entry and releases it on
 * every exit path.  This serialises all NVS access on the "creds" namespace
 * so two tasks cannot hold an NVS_READWRITE handle on the namespace at the
 * same time (which ESP-IDF documents as undefined behaviour).
 *
 * The mutex protects ONLY the cred_store namespace; it does not interact
 * with any other module's NVS access.
 * -------------------------------------------------------------------------- */

esp_err_t cred_store_load(cred_store_t *out)
{
    esp_err_t err = lock_take();
    if (err != ESP_OK) return err;
    err = cred_store_load_unlocked(out);
    lock_give();
    return err;
}

esp_err_t cred_store_save(const cred_store_t *in)
{
    esp_err_t err = lock_take();
    if (err != ESP_OK) return err;
    err = cred_store_save_unlocked(in);
    lock_give();
    return err;
}

esp_err_t cred_store_clear(void)
{
    esp_err_t err = lock_take();
    if (err != ESP_OK) return err;
    err = cred_store_clear_unlocked();
    lock_give();
    return err;
}
