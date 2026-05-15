/*
 * cred_store.h -- NVS-backed SCEP credential store
 *
 * Stores four credential items in NVS namespace "creds" (AES-XTS-256 encrypted
 * via the project's existing nvs_keys / nvs partition setup):
 *
 *   dev_key   -- raw RSA-2048 private-key DER (PKCS#8 unencrypted)
 *   dev_cert  -- issued X.509 DER
 *   ca_chain  -- CA/RA certificate chain (PEM or DER; used as trust root for
 *                WPA3-Enterprise RADIUS validation later)
 *   not_after -- uint64 epoch seconds parsed from dev_cert's NotAfter field
 *
 * The native-test build stubs out the NVS layer behind CRED_STORE_NATIVE_TEST.
 * In that mode the in-memory backend is used instead of NVS, and the wolfSSL
 * ASN.1 parser is still called (linked against the wolfssl stubs in test/stubs/).
 *
 * Key material is wiped from stack buffers with force_zero() before any return
 * path, preventing dead-store optimisation from leaking secrets.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* NVS ESP_ERR_NVS_NOT_FOUND -- on-device the value comes from ESP-IDF's
 * nvs.h, which cred_store.c includes directly.  The native-test build does
 * not have nvs.h on the include path; we still want callers (and the
 * test harness) to reference the macro by name, so define it here only
 * when the real header has not been seen.  Order-of-include sensitive:
 * cred_store.h must be included *before* nvs.h on the embedded build, or
 * the same redefinition that wolfssl misc.h warns about gets triggered. */
#if defined(CRED_STORE_NATIVE_TEST) && !defined(ESP_ERR_NVS_NOT_FOUND)
#define ESP_ERR_NVS_NOT_FOUND  0x1102   /* matches ESP-IDF nvs_flash.h */
#endif

/* --------------------------------------------------------------------------
 * Size limits
 * -------------------------------------------------------------------------- */

/* RSA-2048 private key in PKCS#8 unencrypted DER: ~1200 bytes; 2048 gives
 * headroom for any padding wolfSSL may add.  (Legacy ECDSA P-256 was ~121 B;
 * NDES in legacy CryptoAPI/CSP mode requires RSA-2048, hence the larger buf.) */
#define CRED_DEV_KEY_MAX     2048

/* X.509 certificate DER: typically 1–3 KB; 4096 is generous. */
#define CRED_DEV_CERT_MAX    4096

/* CA chain PEM: may contain multiple certs; 8192 handles three CA certs. */
#define CRED_CA_CHAIN_MAX    8192

/* --------------------------------------------------------------------------
 * Credential bundle
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t  dev_key[CRED_DEV_KEY_MAX];
    size_t   dev_key_len;

    uint8_t  dev_cert[CRED_DEV_CERT_MAX];
    size_t   dev_cert_len;

    uint8_t  ca_chain[CRED_CA_CHAIN_MAX];
    size_t   ca_chain_len;

    uint64_t not_after;   /* Unix epoch seconds from dev_cert NotAfter */
} cred_store_t;

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/*
 * cred_store_load -- read all four credential items from NVS.
 *
 * Returns:
 *   ESP_OK              all four items present; *out is fully populated.
 *   ESP_ERR_NVS_NOT_FOUND  at least one item is missing (enrollment needed).
 *   other esp_err_t     NVS read error.
 */
esp_err_t cred_store_load(cred_store_t *out);

/*
 * cred_store_save -- write all four credential items to NVS atomically.
 *
 * Writes each blob then calls nvs_commit once at the end.  Callers should
 * treat any non-ESP_OK return as a partial-write failure and call
 * cred_store_clear() before retrying.
 */
esp_err_t cred_store_save(const cred_store_t *in);

/*
 * cred_store_clear -- erase the entire "creds" NVS namespace.
 *
 * Called on certificate revocation or before re-enrollment.  All four keys
 * are removed; subsequent cred_store_load() will return ESP_ERR_NVS_NOT_FOUND.
 */
esp_err_t cred_store_clear(void);

/*
 * cred_store_parse_not_after -- extract NotAfter as Unix epoch seconds.
 *
 * Pure function; does not touch NVS.  Native-testable.
 *
 * Parameters:
 *   cert_der  -- DER-encoded X.509 certificate.
 *   cert_len  -- byte length of cert_der.
 *   out_epoch -- receives the NotAfter value as seconds since 1970-01-01 UTC.
 *
 * Returns:
 *   ESP_OK      on success.
 *   ESP_FAIL    if the DER cannot be parsed or NotAfter is absent.
 */
esp_err_t cred_store_parse_not_after(const uint8_t *cert_der,
                                     size_t         cert_len,
                                     uint64_t      *out_epoch);

/*
 * cred_store_parse_not_before -- extract NotBefore as Unix epoch seconds.
 *
 * Pure function; does not touch NVS.  Native-testable.
 * Used by SCEP_NO_NTP_USE_ISSUANCE_TIME mode to set the local clock from
 * the CA-attested issuance time after a fresh enrollment.
 *
 * Parameters:
 *   cert_der  -- DER-encoded X.509 certificate.
 *   cert_len  -- byte length of cert_der.
 *   out_epoch -- receives the NotBefore value as seconds since 1970-01-01 UTC.
 *
 * Returns:
 *   ESP_OK      on success.
 *   ESP_FAIL    if the DER cannot be parsed or NotBefore is absent.
 */
esp_err_t cred_store_parse_not_before(const uint8_t *cert_der,
                                      size_t         cert_len,
                                      uint64_t      *out_epoch);
