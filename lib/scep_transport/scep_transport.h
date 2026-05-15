/*
 * scep_transport.h -- HTTPS transport for SCEP (RFC 8894)
 *
 * Pure C interface; implementation (scep_transport.c) uses ESP-IDF's
 * esp_http_client with mbedTLS as the TLS backend.
 *
 * Two operations:
 *
 *   GetCACert  -- HTTP GET  <base_url>?operation=GetCACert
 *                 Response: DER-encoded PKCS#7 degenerate SignedData holding
 *                 the CA / RA certificate chain.
 *
 *   PKIOperation -- HTTP POST <base_url>?operation=PKIOperation
 *                   Content-Type: application/x-pki-message
 *                   Body: binary PKCS#7 CertificationRequest message.
 *                   Response: binary PKCS#7 CertRep message.
 *
 * TLS trust anchor:
 *   The CA bundle for scep.irix.systems is embedded from main/certs/scep_ca.pem
 *   via EMBED_TXTFILES in main/CMakeLists.txt.  The symbols are declared extern
 *   here so scep_transport.c can reference them without pulling in the
 *   linker-script details.  When SCEP_TRANSPORT_NATIVE_TEST is defined these
 *   symbols are not needed and the TLS layer is not compiled.
 *
 * Memory:
 *   Responses are allocated in PSRAM (MALLOC_CAP_SPIRAM) via the caller-
 *   supplied alloc/free pair.  Callers must free *out_p7 when done.
 *
 * Return values (int):
 *    0  -- success
 *   <0  -- error (see SCEP_TRANSPORT_ERR_* below)
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* --------------------------------------------------------------------------
 * Error codes
 * -------------------------------------------------------------------------- */
#define SCEP_TRANSPORT_OK               0
#define SCEP_TRANSPORT_ERR_ALLOC       -1   /* heap_caps_malloc / alloc() failed */
#define SCEP_TRANSPORT_ERR_HTTP        -2   /* esp_http_client_* error */
#define SCEP_TRANSPORT_ERR_HTTP_STATUS -3   /* HTTP response code != 200 */
#define SCEP_TRANSPORT_ERR_EMPTY_BODY  -4   /* Server returned 200 but no body */
#define SCEP_TRANSPORT_ERR_INVALID_ARG -5   /* NULL pointer argument */
#define SCEP_TRANSPORT_ERR_URL_TOO_LONG -6  /* base_url too long to build query */

/* --------------------------------------------------------------------------
 * TLS trust anchor linker symbols (populated by EMBED_TXTFILES)
 *
 * These are only declared, never defined, here.  The definition lives in the
 * linker-generated object produced from main/certs/scep_ca.pem.
 *
 * Do NOT reference these symbols in native test builds.
 * -------------------------------------------------------------------------- */
#if !defined(SCEP_TRANSPORT_NATIVE_TEST) && !defined(SCEP_CA_PEM_EMBEDDED)
extern const uint8_t scep_ca_pem_start[] asm("_binary_scep_ca_pem_start");
extern const uint8_t scep_ca_pem_end[]   asm("_binary_scep_ca_pem_end");
#define SCEP_CA_PEM_EMBEDDED 1
#endif

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/*
 * scep_http_get_cacert -- fetch the CA/RA certificate chain from the SCEP
 * server using the GetCACert operation (GET request).
 *
 * Parameters:
 *   base_url  -- SCEP endpoint, e.g. "https://scep.irix.systems/certsrv/mscep/mscep.dll"
 *   out_p7    -- receives a pointer to the allocated response body (PKCS#7 DER).
 *                Must be freed by the caller via free_().
 *   out_len   -- receives the byte length of *out_p7.
 *   alloc     -- allocator; pass heap_caps_malloc_prefer(sz, MALLOC_CAP_SPIRAM)
 *                or a test stub.
 *   free_     -- matching deallocator (free or heap_caps_free).
 *
 * Returns SCEP_TRANSPORT_OK on success or a SCEP_TRANSPORT_ERR_* code.
 */
int scep_http_get_cacert(const char  *base_url,
                         uint8_t    **out_p7,
                         size_t      *out_len,
                         void       *(*alloc)(size_t),
                         void       (*free_)(void *));

/*
 * scep_http_pkioperation -- send a PKCS#7 PKIOperation request and receive
 * the server's CertRep response (POST request).
 *
 * Parameters:
 *   base_url  -- SCEP endpoint URL (same as above).
 *   p7_in     -- binary PKCS#7 message to POST.
 *   p7_in_len -- byte length of p7_in.
 *   out_p7    -- receives a pointer to the allocated response body.
 *                Must be freed by the caller via free_().
 *   out_len   -- receives the byte length of *out_p7.
 *   alloc     -- allocator.
 *   free_     -- matching deallocator.
 *
 * Returns SCEP_TRANSPORT_OK on success or a SCEP_TRANSPORT_ERR_* code.
 */
int scep_http_pkioperation(const char  *base_url,
                           const uint8_t *p7_in,
                           size_t         p7_in_len,
                           uint8_t      **out_p7,
                           size_t        *out_len,
                           void         *(*alloc)(size_t),
                           void         (*free_)(void *));
