/*
 * scep_enroll.h -- SCEP enrollment orchestrator for esp-tty
 *
 * Single public entry point: scep_enroll().  Coordinates the protocol agent
 * (lib/scep_proto/), the HTTPS transport (lib/scep_transport/), and the
 * credential store (lib/cred_store/) to enroll the device with an NDES CA.
 *
 * Flow:
 *   1. GetCACert  -> scep_http_get_cacert() -> scep_parse_getcacert()
 *   2. Keygen     -> scep_generate_keypair() (RSA-2048, WC_RNG)
 *   3. Build self-signed cert -> scep_build_self_signed_cert()
 *   4. Build CSR  -> scep_build_csr()
 *   5. Build PKCSReq message -> scep_build_pkimessage_pkcsreq()
 *   6. Send       -> scep_http_pkioperation()
 *   7. Parse      -> scep_parse_certrep()
 *   8. On SUCCESS -> cred_store_save()
 *
 * The common name for the CSR is "<DEVICE_HOSTNAME>-<mac>" where mac is the
 * 12-hex-char lowercase string derived from esp_wifi_get_mac().
 *
 * On FAILURE or PENDING, the failInfo code is logged with a human-readable
 * description.  The function returns ESP_FAIL; the caller should decide
 * whether to retry.
 *
 * Depends on:
 *   lib/scep_proto/scep_proto.h   -- protocol primitives (other agent)
 *   lib/scep_transport/           -- HTTPS transport (this agent)
 *   lib/cred_store/               -- NVS credential store (this agent)
 */

#pragma once

#include "esp_err.h"

/*
 * scep_enroll -- enroll the device with the SCEP CA at scep_url.
 *
 * Parameters:
 *   scep_url           -- HTTPS SCEP endpoint, e.g.
 *                         "https://scep.irix.systems/certsrv/mscep/mscep.dll"
 *   challenge_password -- NDES static challenge password
 *   common_name        -- X.509 CN for the certificate request.  If NULL,
 *                         the function derives "<DEVICE_HOSTNAME>-<mac>".
 *
 * Returns:
 *   ESP_OK              -- enrollment succeeded; credentials saved to NVS via
 *                         cred_store_save().
 *   ESP_ERR_SCEP_PENDING -- CA returned pkiStatus PENDING; the request is
 *                         queued for manual NDES approval.  The caller should
 *                         wait for human approval (minutes to hours) before
 *                         retrying -- do NOT retry immediately or a fresh
 *                         transactionID will flood the CA.  wifi.c (smart
 *                         mode) honours this by sleeping
 *                         SCEP_PENDING_RETRY_DELAY_MS (default 30 min) before
 *                         the next bootstrap-full pass; if a cached cert is
 *                         still valid the device may also bring up enterprise
 *                         during the backoff window.  Other callers (e.g.
 *                         cert_renewer) should apply an equivalent long delay
 *                         when they receive this value rather than treating
 *                         it like a generic ESP_FAIL.
 *   ESP_FAIL            -- enrollment failed (FAILURE pkiStatus, or HTTP /
 *                         crypto error).  Logs describe the failure.
 *   ESP_ERR_NO_MEM      -- PSRAM allocation failed.
 *
 * ESP_ERR_SCEP_PENDING is defined as (ESP_FAIL - 1) so it is a distinct
 * negative value that callers can test with ==.
 */
#define ESP_ERR_SCEP_PENDING  ((esp_err_t)(ESP_FAIL - 1))

esp_err_t scep_enroll(const char *scep_url,
                      const char *challenge_password,
                      const char *common_name);
