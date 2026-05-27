/*
 * scep_transport.c -- HTTPS transport for SCEP (RFC 8894), ESP-IDF impl.
 *
 * Uses esp_http_client (mbedTLS backend) for TLS-verified HTTP requests.
 *
 * TLS trust anchor: main/certs/scep_ca.pem embedded via EMBED_TXTFILES.
 * The PEM file must include the full chain from the SCEP server cert up to
 * (and including) the root CA.
 *
 * Response bodies are read into PSRAM-backed buffers allocated via the
 * caller-supplied alloc/free pair.  The initial buffer is RESP_INIT_BYTES;
 * if the server sends more data the buffer is re-allocated (doubled) until
 * either the data fits or we run out of PSRAM.
 *
 * Both operations share a common internal implementation (_scep_http_request)
 * that handles connection setup, TLS verification, request send, and
 * chunked response accumulation.
 */

#include "scep_transport.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>

#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_heap_caps.h"

/* When building for native host tests the linker-script symbols for the
 * embedded CA cert are not available.  Provide empty stand-ins so the code
 * compiles; the stub's esp_http_client_init ignores cert_pem anyway.
 *
 * Guard: the scep_transport.h extern declarations for scep_ca_pem_start /
 * scep_ca_pem_end are emitted only when SCEP_CA_PEM_EMBEDDED is defined (set
 * by that header on the first inclusion when neither SCEP_TRANSPORT_NATIVE_TEST
 * nor SCEP_CA_PEM_EMBEDDED was already defined).  A build that defines neither
 * flag has no embedded cert and no externs -- the reference sites below are
 * guarded with #if so that the linker does not see undefined symbol references.
 */
#if defined(SCEP_TRANSPORT_NATIVE_TEST)
static const uint8_t scep_ca_pem_start[] = { 0 };
static const uint8_t scep_ca_pem_end[]   = { 0 };
#endif

static const char *TAG = "scep_transport";

/* Initial response buffer allocation in PSRAM (bytes).
 * SCEP GetCACert responses are typically 1-4 KB; PKIOperation CertRep can
 * be up to ~8 KB.  Start at 8 KB and double on overflow. */
#define RESP_INIT_BYTES   (8 * 1024)
#define RESP_MAX_BYTES    (64 * 1024)   /* sanity cap -- NDES never exceeds this */

/* Maximum URL length for a SCEP operation URL (base_url + "?operation=PKIOperation"). */
#define SCEP_URL_MAX      512

/* --------------------------------------------------------------------------
 * Internal response accumulator
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t *buf;       /* PSRAM-backed buffer */
    size_t   cap;       /* allocated capacity */
    size_t   len;       /* bytes written so far */
    void    *(*alloc)(size_t);
    void    (*free_)(void *);
    int      oom;       /* set to 1 on allocation failure */
} resp_buf_t;

static esp_err_t resp_buf_init(resp_buf_t *rb,
                               void *(*alloc)(size_t),
                               void (*free_)(void *))
{
    rb->alloc  = alloc;
    rb->free_  = free_;
    rb->len    = 0;
    rb->oom    = 0;
    rb->cap    = RESP_INIT_BYTES;
    rb->buf    = (uint8_t *)alloc(rb->cap);
    if (!rb->buf) {
        rb->oom = 1;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void resp_buf_free(resp_buf_t *rb)
{
    if (rb->buf) {
        rb->free_(rb->buf);
        rb->buf = NULL;
    }
    rb->len = rb->cap = 0;
}

/* Append bytes to the response buffer, growing as needed. */
static int resp_buf_append(resp_buf_t *rb, const uint8_t *data, size_t n)
{
    if (rb->oom) return -1;
    if (rb->len + n > rb->cap) {
        size_t new_cap = rb->cap;
        while (new_cap < rb->len + n) {
            size_t doubled = new_cap * 2;
            /* Detect size_t overflow: if doubling wraps, doubled < new_cap */
            if (doubled < new_cap) {
                ESP_LOGE(TAG, "SCEP response buffer cap overflow");
                rb->oom = 1;
                return -1;
            }
            new_cap = doubled;
            if (new_cap > RESP_MAX_BYTES) {
                ESP_LOGE(TAG, "SCEP response exceeds max size (%u B)", RESP_MAX_BYTES);
                rb->oom = 1;
                return -1;
            }
        }
        uint8_t *nbuf = (uint8_t *)rb->alloc(new_cap);
        if (!nbuf) {
            ESP_LOGE(TAG, "PSRAM realloc failed for %zu B", new_cap);
            rb->oom = 1;
            return -1;
        }
        memcpy(nbuf, rb->buf, rb->len);
        rb->free_(rb->buf);
        rb->buf = nbuf;
        rb->cap = new_cap;
    }
    memcpy(rb->buf + rb->len, data, n);
    rb->len += n;
    return 0;
}

/* --------------------------------------------------------------------------
 * esp_http_client event handler
 * -------------------------------------------------------------------------- */

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    resp_buf_t *rb = (resp_buf_t *)evt->user_data;

    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;

    case HTTP_EVENT_ON_DATA:
        if (evt->data && evt->data_len > 0) {
            if (resp_buf_append(rb, (const uint8_t *)evt->data,
                                (size_t)evt->data_len) != 0) {
                return ESP_FAIL;
            }
        }
        break;

    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH: %zu B received", rb->len);
        break;

    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;

    default:
        break;
    }
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Shared internal request function
 *
 * method    : HTTP_METHOD_GET or HTTP_METHOD_POST
 * url       : fully-formed URL including ?operation=... query string
 * body      : POST body (NULL for GET)
 * body_len  : byte length of body
 * out_p7    : receives pointer to allocated response buffer
 * out_len   : receives response byte count
 * alloc/free_: allocator pair
 * -------------------------------------------------------------------------- */
static int _scep_http_request(esp_http_client_method_t  method,
                              const char               *url,
                              const uint8_t            *body,
                              size_t                    body_len,
                              uint8_t                 **out_p7,
                              size_t                   *out_len,
                              void                    *(*alloc)(size_t),
                              void                    (*free_)(void *))
{
    resp_buf_t rb;
    if (resp_buf_init(&rb, alloc, free_) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to allocate PSRAM response buffer");
        return SCEP_TRANSPORT_ERR_ALLOC;
    }

    esp_http_client_config_t cfg = {
        .url              = url,
        .method           = method,
        .event_handler    = http_event_handler,
        .user_data        = &rb,
        .timeout_ms       = 120000,  /* NDES->ADCS issuance can take 30-60 s */
        .buffer_size      = 4096,
        .buffer_size_tx   = 4096,
        /* TLS trust anchor: scep_ca.pem embedded via EMBED_TXTFILES.
         * cert_pem is a NUL-terminated PEM string; the length includes the
         * terminator (end - start).
         * These references are guarded: scep_ca_pem_start/end are either
         * provided by the linker (SCEP_CA_PEM_EMBEDDED) or as static stubs
         * (SCEP_TRANSPORT_NATIVE_TEST).  Without either flag the header does
         * not emit the extern declarations and these fields are NULL/0 so the
         * http_client falls back to the system trust store. */
#if defined(SCEP_CA_PEM_EMBEDDED) || defined(SCEP_TRANSPORT_NATIVE_TEST)
        .cert_pem         = (const char *)scep_ca_pem_start,
        .cert_len         = (int)(scep_ca_pem_end - scep_ca_pem_start),
#else
        .cert_pem         = NULL,
        .cert_len         = 0,
#endif
        .skip_cert_common_name_check = false,
        .transport_type   = HTTP_TRANSPORT_OVER_SSL,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE(TAG, "esp_http_client_init failed");
        resp_buf_free(&rb);
        return SCEP_TRANSPORT_ERR_HTTP;
    }

    esp_err_t err = ESP_OK;
    int rc = SCEP_TRANSPORT_OK;

    if (method == HTTP_METHOD_POST && body && body_len > 0) {
        if (body_len > (size_t)INT_MAX) {
            ESP_LOGE(TAG, "POST body too large: %zu", body_len);
            rc = SCEP_TRANSPORT_ERR_INVALID_ARG;
            goto cleanup;
        }

        err = esp_http_client_set_header(client,
                                         "Content-Type",
                                         "application/x-pki-message");
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "set Content-Type header: %s", esp_err_to_name(err));
            rc = SCEP_TRANSPORT_ERR_HTTP;
            goto cleanup;
        }

        err = esp_http_client_set_post_field(client, (const char *)body,
                                             (int)body_len);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "set_post_field: %s", esp_err_to_name(err));
            rc = SCEP_TRANSPORT_ERR_HTTP;
            goto cleanup;
        }
    }

    err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_http_client_perform: %s", esp_err_to_name(err));
        rc = SCEP_TRANSPORT_ERR_HTTP;
        goto cleanup;
    }

    int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        ESP_LOGE(TAG, "SCEP HTTP status %d (expected 200) for URL: %s",
                 status, url);
        rc = SCEP_TRANSPORT_ERR_HTTP_STATUS;
        goto cleanup;
    }

    if (rb.oom) {
        ESP_LOGE(TAG, "Response buffer overflow during receive");
        rc = SCEP_TRANSPORT_ERR_ALLOC;
        goto cleanup;
    }

    if (rb.len == 0) {
        ESP_LOGE(TAG, "SCEP server returned 200 but empty body for URL: %s",
                 url);
        rc = SCEP_TRANSPORT_ERR_EMPTY_BODY;
        goto cleanup;
    }

    *out_p7  = rb.buf;
    *out_len = rb.len;
    /* Transfer ownership: don't free rb.buf here. */
    rb.buf = NULL;
    ESP_LOGI(TAG, "SCEP response: %zu B from %s", *out_len, url);

cleanup:
    if (rb.buf) resp_buf_free(&rb);
    esp_http_client_cleanup(client);
    return rc;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int scep_http_get_cacert(const char  *base_url,
                         uint8_t    **out_p7,
                         size_t      *out_len,
                         void       *(*alloc)(size_t),
                         void       (*free_)(void *))
{
    if (!base_url || !out_p7 || !out_len || !alloc || !free_)
        return SCEP_TRANSPORT_ERR_INVALID_ARG;

    char url[SCEP_URL_MAX];
    int n = snprintf(url, sizeof(url), "%s?operation=GetCACert", base_url);
    if (n < 0 || n >= (int)sizeof(url)) {
        ESP_LOGE(TAG, "base_url too long to build GetCACert URL");
        return SCEP_TRANSPORT_ERR_URL_TOO_LONG;
    }

    ESP_LOGI(TAG, "GetCACert: GET %s", url);
    return _scep_http_request(HTTP_METHOD_GET, url,
                              NULL, 0,
                              out_p7, out_len,
                              alloc, free_);
}

int scep_http_pkioperation(const char    *base_url,
                           const uint8_t *p7_in,
                           size_t         p7_in_len,
                           uint8_t      **out_p7,
                           size_t        *out_len,
                           void         *(*alloc)(size_t),
                           void         (*free_)(void *))
{
    if (!base_url || !p7_in || p7_in_len == 0 ||
        !out_p7 || !out_len || !alloc || !free_)
        return SCEP_TRANSPORT_ERR_INVALID_ARG;

    char url[SCEP_URL_MAX];
    int n = snprintf(url, sizeof(url), "%s?operation=PKIOperation", base_url);
    if (n < 0 || n >= (int)sizeof(url)) {
        ESP_LOGE(TAG, "base_url too long to build PKIOperation URL");
        return SCEP_TRANSPORT_ERR_URL_TOO_LONG;
    }

    ESP_LOGI(TAG, "PKIOperation: POST %s (%zu B)", url, p7_in_len);
    return _scep_http_request(HTTP_METHOD_POST, url,
                              p7_in, p7_in_len,
                              out_p7, out_len,
                              alloc, free_);
}
