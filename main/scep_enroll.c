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
#include "mbedtls/build_info.h"
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
/* mbedTLS 4.x: private/ headers for legacy crypto contexts.
 * MBEDTLS_ALLOW_PRIVATE_ACCESS (from ESP-IDF mbedtls esp_config.h) → private_access.h defines
 * MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS which unlocks function declarations. */
#include "mbedtls/private/pk_private.h"
#include "mbedtls/private/rsa.h"
/* esp_fill_random is the low-level RNG available on all ESP32 targets.
 * mbedtls_esp_random() wraps it for the mbedTLS f_rng signature, but its
 * implementation was omitted from the esp-idf 6.0.1 mbedtls port sources
 * in PlatformIO's espressif32@7.0.1 package.  Provide a local shim instead. */
#include "esp_random.h"
static int scep_esp_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}
/* Shims: on mbedTLS 4.x use esp_fill_random-backed RNG directly */
#define SCEP_F_RNG scep_esp_rng
#define SCEP_P_RNG NULL
#else
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#define SCEP_F_RNG mbedtls_ctr_drbg_random
#define SCEP_P_RNG (&ctr_drbg)
#endif
#include "mbedtls/pk.h"

static const char *TAG = "scep_enroll";

/* --------------------------------------------------------------------------
 * PSRAM allocator shim for scep_transport.
 * -------------------------------------------------------------------------- */
static void *psram_alloc(size_t sz)
{
    /* Prefer PSRAM; fall back to internal RAM when CONFIG_SPIRAM=n
     * (e.g. Zero boards with PSRAM disabled for stability). */
    void *p = heap_caps_malloc(sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = heap_caps_malloc(sz, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    return p;
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
#if MBEDTLS_VERSION_NUMBER < 0x04000000
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
#endif

    /* mbedtls_pk_context for the RSA-2048 key.  Initialise NOW (before any
     * `goto done`) so the `done:` cleanup can safely call mbedtls_pk_free()
     * even when an earlier step fails -- otherwise reading an uninitialised
     * pk_context corrupts the stack with garbage pointers and crashes with
     * IllegalInstruction. */
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    /* -- Resolve common name --------------------------------------------
     * Precedence: caller-provided argument > SCEP_CN macro > MAC-derived
     * default of "<DEVICE_HOSTNAME>-<mac>". */
    char cn_buf[64];
    if (!common_name || common_name[0] == '\0') {
#ifdef SCEP_CN
        common_name = SCEP_CN;
#else
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
#endif
    }
    /* Do NOT log full CN at INFO -- it contains the device MAC address and
     * flows over the cleartext udp_log, enabling device tracking.  URL is a
     * shared infrastructure value (not per-device) so it stays at INFO. */
    ESP_LOGI(TAG, "SCEP enrollment starting: URL=%s", scep_url);
    ESP_LOGD(TAG, "SCEP enrollment CN=%s", common_name);

    /* Heap-allocate working buffers in internal RAM.  Credential material
     * (dev_key_der, issued_cert) needs internal RAM; the cert snapshot
     * copies (ra/ca) live in 8-bit addressable internal RAM too since
     * mbedTLS accesses them directly. */
    uint8_t *ra_cert_copy   = NULL;
    uint8_t *ca_cert_copy   = NULL;
    uint8_t *dev_key_der    = NULL;
    uint8_t *self_cert_der  = NULL;
    uint8_t *csr_der        = NULL;
    uint8_t *spki_der       = NULL;
    uint8_t *p7_req         = NULL;
    uint8_t *issued_cert_der = NULL;
    /* cred_store_t is ~14 KB (dev_key 2 KB + dev_cert 4 KB + ca_chain 8 KB + metadata).
     * Stack-allocating it inside a 32 KB FreeRTOS task that is already running
     * mbedTLS RSA scratch (~4-8 KB) and ASN.1 builders would overflow.  Heap
     * allocate from internal RAM (NVS APIs and mbedTLS expect 8-bit accessible
     * memory; this also matches the dev_key_der/issued_cert_der allocator
     * choice above for credentials-bearing buffers). */
    cred_store_t *creds      = NULL;

/* DIAGNOSTIC: prefer PSRAM over internal RAM for SCEP scratch.  On Zero
 * v0.2 silicon the internal-RAM heap's spinlock CAS hangs under SCEP
 * heap pressure; PSRAM heap uses a separate spinlock instance and may
 * avoid the issue.  Falls back to internal RAM if PSRAM unavailable. */
#define ALLOC_BUF(ptr, sz) do { \
    (ptr) = heap_caps_calloc(1, (sz), MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM); \
    if (!(ptr)) (ptr) = heap_caps_calloc(1, (sz), MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL); \
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
    /* `key` is declared + pk_init'd at the top of the function.           */
    /* ------------------------------------------------------------------ */
    ret = scep_generate_keypair(&key, SCEP_F_RNG, SCEP_P_RNG);
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
    /* Private-key size annotates key-lifecycle timing for an off-device
     * observer; drop to LOGD. */
    ESP_LOGD(TAG, "Private key DER: %zu B", dev_key_der_len);

    /* ------------------------------------------------------------------ */
    /* Step 4: Build self-signed transient cert (signer-info cert)         */
    /* ------------------------------------------------------------------ */
    scep_subject_t subject;
    memset(&subject, 0, sizeof(subject));
    subject.common_name = common_name;
#ifdef SCEP_O
    subject.organization = SCEP_O;
#endif
#ifdef SCEP_OU
    subject.organizational_unit = SCEP_OU;
#endif
#ifdef SCEP_C
    subject.country = SCEP_C;
#endif

    size_t self_cert_len = SCEP_MAX_CERT_DER;

    ret = scep_build_self_signed_cert(&subject, &key,
                                      SCEP_F_RNG, SCEP_P_RNG,
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
                         SCEP_F_RNG, SCEP_P_RNG,
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
    /* transactionID is SHA-256(SPKI) -- a stable per-device identifier that
     * an attacker observing the cleartext udp_log could correlate across
     * boots.  Keep diagnostic visibility at LOGD only. */
    ESP_LOGD(TAG, "transactionID: %.16s...", txid);

    /* ------------------------------------------------------------------ */
    /* Step 7: Build PKCSReq pkiMessage                                    */
    /* ------------------------------------------------------------------ */
    size_t p7_req_len = SCEP_MAX_P7_LEN;

    ret = scep_build_pkimessage_pkcsreq(
              csr_der,                 csr_len,
              cab.ra_encrypt_cert_der, cab.ra_encrypt_cert_len,
              &key,
              self_cert_der,           self_cert_len,
              SCEP_F_RNG, SCEP_P_RNG,
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
    /* Initialise to NULL so the done: block's defensive psram_free(p7_resp) is
     * always a safe no-op if we never reach the psram_alloc inside
     * scep_http_pkioperation() (e.g. a future goto done added before this
     * point). */
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

#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    ret = mbedtls_pk_parse_key(&dec_key, dev_key_der, dev_key_der_len,
                               NULL, 0);
#else
    ret = mbedtls_pk_parse_key(&dec_key, dev_key_der, dev_key_der_len,
                               NULL, 0,
                               SCEP_F_RNG, SCEP_P_RNG);
#endif
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_pk_parse_key failed: -0x%04x", (unsigned)(-ret));
        mbedtls_pk_free(&dec_key);
        psram_free(p7_resp);
        p7_resp = NULL;
        goto done;
    }

    size_t issued_cert_len = SCEP_MAX_CERT_DER;
    scep_pki_status_t pki_status = SCEP_PKI_STATUS_UNKNOWN;
    int fail_info = SCEP_FAIL_INFO_NONE;

    prc = scep_parse_certrep(p7_resp, p7_resp_len,
                             txid,
                             &dec_key,
                             SCEP_F_RNG, SCEP_P_RNG,
                             issued_cert_der, &issued_cert_len,
                             &pki_status, &fail_info);

    mbedtls_pk_free(&dec_key);
    psram_free(p7_resp);
    p7_resp = NULL;   /* NULL after explicit free: done: block is a safe net */

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
        ESP_LOGW(TAG, "SCEP enrollment PENDING -- request queued for manual NDES "
                      "approval.  Do NOT retry immediately; wait for CA admin to "
                      "approve the request (use a long backoff, e.g. hours).");
        result = ESP_ERR_SCEP_PENDING;
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
    creds = heap_caps_calloc(1, sizeof(cred_store_t),
                             MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!creds) {
        ESP_LOGE(TAG, "heap_caps_calloc(cred_store_t, %zu B) failed",
                 sizeof(cred_store_t));
        result = ESP_ERR_NO_MEM;
        goto done;
    }

    /* Private key */
    if (dev_key_der_len > CRED_DEV_KEY_MAX) {
        ESP_LOGE(TAG, "Private key DER too large for store (%zu > %u)",
                 dev_key_der_len, CRED_DEV_KEY_MAX);
        goto done;
    }
    memcpy(creds->dev_key, dev_key_der, dev_key_der_len);
    creds->dev_key_len = dev_key_der_len;

    /* Issued cert */
    if (issued_cert_len > CRED_DEV_CERT_MAX) {
        ESP_LOGE(TAG, "Issued cert DER too large for store (%zu > %u)",
                 issued_cert_len, CRED_DEV_CERT_MAX);
        goto done;
    }
    memcpy(creds->dev_cert, issued_cert_der, issued_cert_len);
    creds->dev_cert_len = issued_cert_len;

    /* CA chain -- concatenate every distinct cert the bundle exposed so the
     * RADIUS supplicant has the full path it needs.  In a 2-tier deployment
     * the bundle's three pointers (ca, ra_sign, ra_encrypt) may alias; we
     * dedup by DER content so the chain contains each unique cert exactly
     * once.  Layout in ca_chain:  cert_1_der || cert_2_der || ...  (raw
     * concatenation; consumers walk the buffer with mbedtls_x509_crt_parse
     * which auto-detects DER boundaries via the outer SEQUENCE length).
     *
     * NOTE: in a 3-tier root->intermediate->issuing CA hierarchy the
     * scep_parse_getcacert parser (lib/scep_proto -- out of this scope)
     * returns only one CA pointer + the RA certs; additional intermediates
     * present in the underlying PKCS#7 are NOT exposed by the bundle and
     * therefore cannot be included here.  Fixing that requires extending
     * the parser API.  Flagged. */
    struct { const uint8_t *der; size_t len; } chain_certs[3] = {
        { cab.ca_cert_der,         cab.ca_cert_len },
        { cab.ra_sign_cert_der,    cab.ra_sign_cert_len },
        { cab.ra_encrypt_cert_der, cab.ra_encrypt_cert_len },
    };
    size_t chain_off = 0;
    for (size_t i = 0; i < sizeof(chain_certs)/sizeof(chain_certs[0]); i++) {
        const uint8_t *cder = chain_certs[i].der;
        size_t         clen = chain_certs[i].len;
        if (!cder || clen == 0) continue;
        /* Dedup against already-appended certs (pointer alias OR byte-equal). */
        int already = 0;
        size_t scan = 0;
        while (scan < chain_off) {
            /* DER cert begins with 0x30 (SEQUENCE) + length encoding.  We
             * recompute the next cert's length by reading the ASN.1 length
             * field rather than guessing.  Constant-time not required;
             * this is non-secret CA material. */
            if (scan + 1 > chain_off) break;
            size_t hdr = 0, body = 0;
            uint8_t b1 = creds->ca_chain[scan + 1];
            if (b1 < 0x80) { hdr = 2; body = b1; }
            else {
                size_t n = b1 & 0x7F;
                if (n == 0 || n > 4 || scan + 2 + n > chain_off) break;
                hdr = 2 + n;
                body = 0;
                for (size_t k = 0; k < n; k++)
                    body = (body << 8) | creds->ca_chain[scan + 2 + k];
            }
            size_t whole = hdr + body;
            if (scan + whole > chain_off) break;
            if (whole == clen && memcmp(&creds->ca_chain[scan], cder, clen) == 0) {
                already = 1;
                break;
            }
            scan += whole;
        }
        if (already) continue;
        if (chain_off + clen > CRED_CA_CHAIN_MAX) {
            ESP_LOGW(TAG, "CA chain too large for store (%zu + %zu > %u) -- "
                          "truncating before cert %zu", chain_off, clen,
                          CRED_CA_CHAIN_MAX, i);
            break;
        }
        memcpy(creds->ca_chain + chain_off, cder, clen);
        chain_off += clen;
    }
    creds->ca_chain_len = chain_off;
    ESP_LOGI(TAG, "CA chain assembled: %zu B (deduped from %d bundle slots)",
             creds->ca_chain_len, 3);

    /* NotAfter
     *
     * We refuse to persist credentials when not_after cannot be parsed.
     * Rationale (option a from the audit):
     *   - Storing not_after=0 triggers cert_renewer_decide → RENEW_NOW_CORRUPT
     *     on every boot even though the certificate itself is functionally valid.
     *   - When the SCEP server is temporarily unreachable the device would
     *     re-enroll on every boot instead of using the working cert.
     *   - Leaving the old credentials in place is the correct behaviour: the
     *     cert is usable, and cert_renewer's time-based renewal path will fire
     *     normally once the clock and CA are both healthy.
     *   - If there are NO old credentials (first enrollment) the caller falls
     *     back to its existing "no creds, retry later" handling -- same as a
     *     network failure.  No silent boot-loop of pointless re-enrollments.
     */
    esp_err_t err = cred_store_parse_not_after(issued_cert_der, issued_cert_len,
                                               &creds->not_after);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not parse NotAfter from issued cert: %s -- "
                      "refusing to overwrite credentials with an unusable bundle "
                      "(old creds, if any, remain in place; cert_renewer will retry)",
                 esp_err_to_name(err));
        /* Leave any existing credentials intact. */
        goto done;
    }
    ESP_LOGI(TAG, "Cert NotAfter: epoch %llu", (unsigned long long)creds->not_after);

    /* ------------------------------------------------------------------ */
    /* Step 12: Save credentials to NVS                                    */
    /* ------------------------------------------------------------------ */
    err = cred_store_save(creds);
    /* creds (containing the live RSA-2048 private key) is zeroized + freed in
     * the done: cleanup below on every exit path -- success and failure. */

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "cred_store_save failed: %s", esp_err_to_name(err));
        goto done;
    }

    ESP_LOGI(TAG, "SCEP enrollment complete -- credentials stored in NVS");
    result = ESP_OK;

done:
    /* heap_caps_free(NULL) is safe per ESP-IDF docs (mirrors free(NULL) POSIX
     * contract; implemented in heap/heap_caps.c).  All pointers below are
     * NULL-initialised at declaration so unconditional calls are safe.
     * ra_cert_copy, ca_cert_copy, self_cert_der, csr_der, spki_der, p7_req
     * are guarded below without if() wrappers for that reason.
     * dev_key_der and issued_cert_der are guarded with if() because they
     * carry a zeroize step that must not run on a NULL pointer.
     *
     * p7_resp is psram_alloc'd inside scep_http_pkioperation(); the two
     * explicit frees above each set it to NULL so this call is a no-op on
     * the normal paths and a true safety net if a future goto done is added
     * before the explicit frees.
     * ca_p7 is psram_alloc'd by scep_http_get_cacert(); freed explicitly in
     * the GetCACert error paths above and in the done: block below. */
    psram_free(p7_resp);

    /* mbedtls_pk_free is safe to call even if the key was never set up
     * (mbedtls_pk_init + mbedtls_pk_free with no intervening setup is a no-op).
     * However if the key was set up and freed in step 8, calling free again
     * on the already-freed context would be a double-free.  We detect this
     * via pk_info: pk_init sets it to NULL, pk_free leaves it NULL. */
    if (mbedtls_pk_get_type(&key) != MBEDTLS_PK_NONE) {
        mbedtls_pk_free(&key);
        zeroize(&key, sizeof(key));
    }
#if MBEDTLS_VERSION_NUMBER < 0x04000000
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#endif
    psram_free(ca_p7);   /* NULL-initialised; safe no-op when not allocated */
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

    if (creds) {
        /* Zeroize the entire bundle: even ca_chain (non-secret) shares the
         * allocation with dev_key (secret).  Single zeroize keeps the wipe
         * path simple and avoids a partial-wipe bug if the layout changes. */
        zeroize(creds, sizeof(*creds));
        heap_caps_free(creds);
    }

    return result;
}
