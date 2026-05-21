/*
 * scep_enroll.c -- SCEP enrollment orchestrator
 *
 * Ties together:
 *   - lib/scep_proto/     (protocol agent's library -- CSR, PKCS#7, CertRep)
 *   - lib/scep_transport/ (HTTPS transport -- GetCACert, PKIOperation)
 *   - lib/cred_store/     (NVS-backed credential persistence)
 *
 * Key algorithm: RSA-2048 with SHA-256 PKCS#1v1.5.
 * Rationale: Microsoft NDES in legacy CryptoAPI/CSP mode rejects ECDSA-signed
 * pkiMessages (failInfo=1 badMessageCheck).  RFC 8894 §3.5.2 requires RSA for
 * legacy NDES interoperability.  Confirmed end-to-end with PyScep probe.
 *
 * Control flow:
 *   1. GetCACert -> scep_http_get_cacert() -> scep_parse_getcacert()
 *   2. Generate RSA-2048 keypair -> scep_generate_keypair()
 *   3. Export private key DER for storage
 *   4. Build self-signed transient cert -> scep_build_self_signed_cert()
 *   5. Build CSR -> scep_build_csr()
 *   6. Derive transactionID -> scep_transaction_id()
 *   7. Build PKCSReq message -> scep_build_pkimessage_pkcsreq()
 *   8. Wipe key material from stack
 *   9. Send -> scep_http_pkioperation()
 *  10. Parse response -> scep_parse_certrep()
 *  11. On SUCCESS -> cred_store_parse_not_after() + cred_store_save()
 *  12. On FAILURE/PENDING -> log failInfo + return ESP_FAIL
 */

#include "scep_enroll.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"

#include "config.h"   /* DEVICE_HOSTNAME */

/* Protocol agent's library */
#include "scep_proto.h"

/* This agent's libraries */
#include "scep_transport.h"
#include "cred_store.h"
#include "zeroize.h"

/* mbedTLS for key operations */
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static const char *TAG = "scep_enroll";

/* --------------------------------------------------------------------------
 * PSRAM allocator shim for scep_transport.
 * -------------------------------------------------------------------------- */
static void *psram_alloc(size_t sz)
{
    return heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static void psram_free(void *p)
{
    heap_caps_free(p);
}

/* --------------------------------------------------------------------------
 * failInfo -> human-readable string
 * -------------------------------------------------------------------------- */
static const char *fail_info_str(int fi)
{
    switch (fi) {
    case SCEP_FAIL_INFO_BAD_ALG:           return "badAlg (0): unsupported algorithm";
    case SCEP_FAIL_INFO_BAD_MESSAGE_CHECK: return "badMessageCheck (1): integrity error";
    case SCEP_FAIL_INFO_BAD_REQUEST:       return "badRequest (2): cert request rejected by policy";
    case SCEP_FAIL_INFO_BAD_TIME:          return "badTime (3): message time outside valid window";
    case SCEP_FAIL_INFO_BAD_CERT_ID:       return "badCertId (4): unknown certificate";
    case SCEP_FAIL_INFO_NONE:              return "(none)";
    default:                               return "(unknown failInfo code)";
    }
}

/* --------------------------------------------------------------------------
 * scep_enroll
 * -------------------------------------------------------------------------- */

esp_err_t scep_enroll(const char *scep_url,
                      const char *challenge_password,
                      const char *common_name)
{
    if (!scep_url || !challenge_password) {
        ESP_LOGE(TAG, "scep_enroll: NULL required argument");
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t result = ESP_FAIL;
    int ret;

    /* -- mbedTLS RNG context -------------------------------------------- */
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)"scep_enroll", 11);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", (unsigned)(-ret));
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return ESP_FAIL;
    }

    /* -- Derive common name from MAC if not provided -------------------- */
    char cn_buf[64];
    if (!common_name || common_name[0] == '\0') {
        uint8_t mac[6] = {0};
        esp_err_t merr = esp_wifi_get_mac(WIFI_IF_STA, mac);
        if (merr != ESP_OK) {
            ESP_LOGW(TAG, "esp_wifi_get_mac: %s -- using hostname only",
                     esp_err_to_name(merr));
            snprintf(cn_buf, sizeof(cn_buf), "%s", DEVICE_HOSTNAME);
        } else {
            snprintf(cn_buf, sizeof(cn_buf),
                     "%s-%02x%02x%02x%02x%02x%02x",
                     DEVICE_HOSTNAME,
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        common_name = cn_buf;
    }
    ESP_LOGI(TAG, "SCEP enrollment starting: URL=%s CN=%s", scep_url, common_name);

    /* -- Heap-allocate working buffers in internal RAM.
     *
     * These were formerly `static` which pinned ~14 KB of BSS permanently and
     * made the function non-reentrant.  Heap allocation costs nothing during
     * boot and frees the BSS.  Credential material (dev_key_der, issued_cert)
     * goes to internal RAM; the cert snapshot copies (ra/ca) can be 8-bit
     * addressable internal RAM as well since mbedTLS accesses them directly. */
    uint8_t *ra_cert_copy   = NULL;
    uint8_t *ca_cert_copy   = NULL;
    uint8_t *dev_key_der    = NULL;
    uint8_t *self_cert_der  = NULL;
    uint8_t *csr_der        = NULL;
    uint8_t *spki_der       = NULL;
    uint8_t *p7_req         = NULL;
    uint8_t *issued_cert_der = NULL;

#define ALLOC_BUF(ptr, sz) do { \
    (ptr) = heap_caps_calloc(1, (sz), MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL); \
    if (!(ptr)) { \
        ESP_LOGE(TAG, "scep_enroll: failed to allocate %zu B for " #ptr, (size_t)(sz)); \
        goto done; \
    } \
} while (0)

    ALLOC_BUF(ra_cert_copy,    SCEP_MAX_CA_BUNDLE_CERT_DER);
    ALLOC_BUF(ca_cert_copy,    SCEP_MAX_CA_BUNDLE_CERT_DER);
    ALLOC_BUF(dev_key_der,     CRED_DEV_KEY_MAX);
    ALLOC_BUF(self_cert_der,   SCEP_MAX_CERT_DER);
    ALLOC_BUF(csr_der,         SCEP_MAX_CSR_DER);
    ALLOC_BUF(spki_der,        320);   /* RSA-2048 SPKI DER is ~294 bytes */
    ALLOC_BUF(p7_req,          SCEP_MAX_P7_LEN);
    ALLOC_BUF(issued_cert_der, SCEP_MAX_CERT_DER);

#undef ALLOC_BUF

    /* ------------------------------------------------------------------ */
    /* Step 1: GetCACert                                                    */
    /* ------------------------------------------------------------------ */
    uint8_t *ca_p7     = NULL;
    size_t   ca_p7_len = 0;

    int trc = scep_http_get_cacert(scep_url, &ca_p7, &ca_p7_len,
                                   psram_alloc, psram_free);
    if (trc != SCEP_TRANSPORT_OK) {
        ESP_LOGE(TAG, "GetCACert HTTP transport error: %d", trc);
        goto done;
    }
    ESP_LOGI(TAG, "GetCACert: received %zu B of PKCS#7", ca_p7_len);

    scep_cacert_bundle_t cab;
    memset(&cab, 0, sizeof(cab));
    int prc = scep_parse_getcacert(ca_p7, ca_p7_len, &cab);
    if (prc != 0) {
        ESP_LOGE(TAG, "scep_parse_getcacert failed: %d", prc);
        psram_free(ca_p7);
        ca_p7 = NULL;
        goto done;
    }
    ESP_LOGI(TAG, "CA cert: %zu B  RA-encrypt cert: %zu B  (single=%d)",
             cab.ca_cert_len, cab.ra_encrypt_cert_len, cab.single_cert);

    /* Snapshot certs we need into local buffers so they survive any
     * subsequent allocations that might reuse the PSRAM region. */
    if (cab.ra_encrypt_cert_len > SCEP_MAX_CA_BUNDLE_CERT_DER ||
        cab.ca_cert_len         > SCEP_MAX_CA_BUNDLE_CERT_DER) {
        ESP_LOGE(TAG, "CA bundle cert too large for snapshot");
        psram_free(ca_p7);
        ca_p7 = NULL;
        goto done;
    }
    memcpy(ra_cert_copy, cab.ra_encrypt_cert_der, cab.ra_encrypt_cert_len);
    memcpy(ca_cert_copy, cab.ca_cert_der,         cab.ca_cert_len);
    cab.ra_encrypt_cert_der = ra_cert_copy;
    cab.ca_cert_der         = ca_cert_copy;

    /* ------------------------------------------------------------------ */
    /* Steps 2-3: Generate RSA-2048 keypair and export private key DER     */
    /* ------------------------------------------------------------------ */
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    ret = scep_generate_keypair(&key, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "scep_generate_keypair failed: -0x%04x", (unsigned)(-ret));
        goto done;
    }
    ESP_LOGI(TAG, "RSA-2048 keypair generated");

    /* Export private key to DER now, before any goto that would call
     * mbedtls_pk_free().  We need it later for cred_store_save(). */
    int dev_key_der_len_i = mbedtls_pk_write_key_der(&key, dev_key_der, CRED_DEV_KEY_MAX);
    if (dev_key_der_len_i <= 0) {
        ESP_LOGE(TAG, "mbedtls_pk_write_key_der failed: -0x%04x",
                 (unsigned)(-dev_key_der_len_i));
        goto done;
    }
    /* mbedtls_pk_write_key_der writes at end of buffer; move to front */
    size_t dev_key_der_len = (size_t)dev_key_der_len_i;
    memmove(dev_key_der, dev_key_der + CRED_DEV_KEY_MAX - dev_key_der_len,
            dev_key_der_len);
    ESP_LOGI(TAG, "Private key DER: %zu B", dev_key_der_len);

    /* ------------------------------------------------------------------ */
    /* Step 4: Build self-signed transient cert (signer-info cert)         */
    /* ------------------------------------------------------------------ */
    scep_subject_t subject;
    memset(&subject, 0, sizeof(subject));
    subject.common_name = common_name;

    size_t self_cert_len = SCEP_MAX_CERT_DER;

    ret = scep_build_self_signed_cert(&subject, &key,
                                      mbedtls_ctr_drbg_random, &ctr_drbg,
                                      self_cert_der, &self_cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "scep_build_self_signed_cert failed: -0x%04x", (unsigned)(-ret));
        goto done;
    }
    ESP_LOGI(TAG, "Self-signed cert: %zu B", self_cert_len);

    /* ------------------------------------------------------------------ */
    /* Step 5: Build PKCS#10 CSR                                           */
    /* ------------------------------------------------------------------ */
    size_t csr_len = SCEP_MAX_CSR_DER;

    ret = scep_build_csr(&subject, &key, challenge_password,
                         mbedtls_ctr_drbg_random, &ctr_drbg,
                         csr_der, &csr_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "scep_build_csr failed: -0x%04x", (unsigned)(-ret));
        goto done;
    }
    ESP_LOGI(TAG, "CSR: %zu B", csr_len);

    /* ------------------------------------------------------------------ */
    /* Step 6: Derive transactionID from RSA SPKI                         */
    /* ------------------------------------------------------------------ */
    int spki_len_i = mbedtls_pk_write_pubkey_der(&key, spki_der, 320);
    if (spki_len_i <= 0) {
        ESP_LOGE(TAG, "mbedtls_pk_write_pubkey_der failed: -0x%04x",
                 (unsigned)(-spki_len_i));
        goto done;
    }
    /* mbedtls_pk_write_pubkey_der writes at end of buffer */
    size_t spki_len = (size_t)spki_len_i;
    const uint8_t *spki_start = spki_der + 320 - spki_len;

    char txid[SCEP_TRANSACTION_ID_HEX_LEN + 1];
    ret = scep_transaction_id(spki_start, spki_len, txid, sizeof(txid));
    if (ret != 0) {
        ESP_LOGE(TAG, "scep_transaction_id failed: %d", ret);
        goto done;
    }
    ESP_LOGI(TAG, "transactionID: %.16s...", txid);

    /* ------------------------------------------------------------------ */
    /* Step 7: Build PKCSReq pkiMessage                                    */
    /* ------------------------------------------------------------------ */
    size_t p7_req_len = SCEP_MAX_P7_LEN;

    ret = scep_build_pkimessage_pkcsreq(
              csr_der,                 csr_len,
              cab.ra_encrypt_cert_der, cab.ra_encrypt_cert_len,
              &key,
              self_cert_der,           self_cert_len,
              mbedtls_ctr_drbg_random, &ctr_drbg,
              txid,
              p7_req,                  &p7_req_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "scep_build_pkimessage_pkcsreq failed: %d", ret);
        goto done;
    }
    ESP_LOGI(TAG, "PKCSReq pkiMessage built: %zu B", p7_req_len);

    /* ------------------------------------------------------------------ */
    /* Step 8: Wipe key material before network I/O                        */
    /* ------------------------------------------------------------------ */
    mbedtls_pk_free(&key);
    zeroize(csr_der,      SCEP_MAX_CSR_DER);
    zeroize(self_cert_der, SCEP_MAX_CERT_DER);
    zeroize(spki_der,     320);

    /* ------------------------------------------------------------------ */
    /* Step 9: PKIOperation (POST)                                         */
    /* ------------------------------------------------------------------ */
    uint8_t *p7_resp     = NULL;
    size_t   p7_resp_len = 0;

    trc = scep_http_pkioperation(scep_url,
                                 p7_req, p7_req_len,
                                 &p7_resp, &p7_resp_len,
                                 psram_alloc, psram_free);
    zeroize(p7_req, p7_req_len);   /* no longer needed */

    if (trc != SCEP_TRANSPORT_OK) {
        ESP_LOGE(TAG, "PKIOperation HTTP transport error: %d", trc);
        goto done;
    }
    ESP_LOGI(TAG, "PKIOperation response: %zu B", p7_resp_len);

    /* ------------------------------------------------------------------ */
    /* Step 10: Parse CertRep                                              */
    /* ------------------------------------------------------------------ */

    /* Reconstruct an mbedtls_pk_context for decryption from the stored DER */
    mbedtls_pk_context dec_key;
    mbedtls_pk_init(&dec_key);

    ret = mbedtls_pk_parse_key(&dec_key, dev_key_der, dev_key_der_len,
                               NULL, 0,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_pk_parse_key failed: -0x%04x", (unsigned)(-ret));
        psram_free(p7_resp);
        goto done;
    }

    size_t issued_cert_len = SCEP_MAX_CERT_DER;
    scep_pki_status_t pki_status = SCEP_PKI_STATUS_UNKNOWN;
    int fail_info = SCEP_FAIL_INFO_NONE;

    prc = scep_parse_certrep(p7_resp, p7_resp_len,
                             txid,
                             &dec_key,
                             mbedtls_ctr_drbg_random, &ctr_drbg,
                             issued_cert_der, &issued_cert_len,
                             &pki_status, &fail_info);

    mbedtls_pk_free(&dec_key);
    psram_free(p7_resp);
    p7_resp = NULL;

    if (prc != 0) {
        ESP_LOGE(TAG, "scep_parse_certrep structural error: %d", prc);
        goto done;
    }

    /* ------------------------------------------------------------------ */
    /* Step 11: Handle pkiStatus                                           */
    /* ------------------------------------------------------------------ */
    if (pki_status == SCEP_PKI_STATUS_FAILURE) {
        ESP_LOGE(TAG, "SCEP enrollment FAILED: failInfo=%s",
                 fail_info_str(fail_info));
        goto done;
    }

    if (pki_status == SCEP_PKI_STATUS_PENDING) {
        ESP_LOGW(TAG, "SCEP enrollment PENDING -- request queued for manual approval");
        goto done;
    }

    if (pki_status != SCEP_PKI_STATUS_SUCCESS) {
        ESP_LOGE(TAG, "Unexpected pkiStatus: %d", (int)pki_status);
        goto done;
    }

    ESP_LOGI(TAG, "SCEP pkiStatus: SUCCESS -- cert %zu B", issued_cert_len);

    /* ------------------------------------------------------------------ */
    /* Step 11b: Parse NotAfter and build credential bundle                */
    /* ------------------------------------------------------------------ */
    cred_store_t creds;
    memset(&creds, 0, sizeof(creds));

    /* Private key */
    if (dev_key_der_len > CRED_DEV_KEY_MAX) {
        ESP_LOGE(TAG, "Private key DER too large for store (%zu > %u)",
                 dev_key_der_len, CRED_DEV_KEY_MAX);
        goto done;
    }
    memcpy(creds.dev_key, dev_key_der, dev_key_der_len);
    creds.dev_key_len = dev_key_der_len;

    /* Issued cert */
    if (issued_cert_len > CRED_DEV_CERT_MAX) {
        ESP_LOGE(TAG, "Issued cert DER too large for store (%zu > %u)",
                 issued_cert_len, CRED_DEV_CERT_MAX);
        goto done;
    }
    memcpy(creds.dev_cert, issued_cert_der, issued_cert_len);
    creds.dev_cert_len = issued_cert_len;

    /* CA chain */
    if (cab.ca_cert_len > CRED_CA_CHAIN_MAX) {
        ESP_LOGW(TAG, "CA chain too large for store (%zu > %u) -- truncating",
                 cab.ca_cert_len, CRED_CA_CHAIN_MAX);
        cab.ca_cert_len = CRED_CA_CHAIN_MAX;
    }
    memcpy(creds.ca_chain, cab.ca_cert_der, cab.ca_cert_len);
    creds.ca_chain_len = cab.ca_cert_len;

    /* NotAfter */
    esp_err_t err = cred_store_parse_not_after(issued_cert_der, issued_cert_len,
                                               &creds.not_after);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not parse NotAfter from issued cert: %s -- "
                      "storing 0 (expiry check will be skipped)",
                 esp_err_to_name(err));
        creds.not_after = 0;
    } else {
        ESP_LOGI(TAG, "Cert NotAfter: epoch %llu", (unsigned long long)creds.not_after);
    }

    /* ------------------------------------------------------------------ */
    /* Step 12: Save credentials to NVS                                    */
    /* ------------------------------------------------------------------ */
    err = cred_store_save(&creds);
    zeroize(&creds, sizeof(creds));

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "cred_store_save failed: %s", esp_err_to_name(err));
        goto done;
    }

    ESP_LOGI(TAG, "SCEP enrollment complete -- credentials stored in NVS");
    result = ESP_OK;

done:
    /* mbedtls_pk_free is safe to call even if the key was never set up
     * (mbedtls_pk_init + mbedtls_pk_free with no intervening setup is a no-op).
     * However if the key was set up and freed in step 8, calling free again
     * on the already-freed context would be a double-free.  We detect this
     * via pk_info: pk_init sets it to NULL, pk_free leaves it NULL. */
    if (mbedtls_pk_get_type(&key) != MBEDTLS_PK_NONE) {
        mbedtls_pk_free(&key);
        zeroize(&key, sizeof(key));
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (ca_p7) {
        psram_free(ca_p7);
    }
    if (dev_key_der) {
        zeroize(dev_key_der, CRED_DEV_KEY_MAX);
        heap_caps_free(dev_key_der);
    }
    if (issued_cert_der) {
        zeroize(issued_cert_der, SCEP_MAX_CERT_DER);
        heap_caps_free(issued_cert_der);
    }
    heap_caps_free(ra_cert_copy);
    heap_caps_free(ca_cert_copy);
    heap_caps_free(self_cert_der);
    heap_caps_free(csr_der);
    heap_caps_free(spki_der);
    heap_caps_free(p7_req);

    return result;
}
