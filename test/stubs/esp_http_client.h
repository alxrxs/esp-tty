/* Native test stub: esp_http_client.h
 *
 * Programmable fake for the ESP-IDF HTTP client used by lib/scep_transport.
 *
 * Tests set the stub state before calling scep_http_get_cacert /
 * scep_http_pkioperation and inspect what was captured afterward.
 *
 * All functions are declared here as regular (non-inline) prototypes so
 * the test .c file can provide the definitions in a companion stub .c
 * (test/native/test_scep_transport/esp_http_client_stub.c).  This avoids
 * duplicate-symbol errors when multiple translation units include the header.
 *
 * Usage pattern (per test):
 *   esp_http_client_stub_reset();
 *   esp_http_client_stub_set_perform_result(ESP_OK);
 *   esp_http_client_stub_set_status_code(200);
 *   esp_http_client_stub_set_response_body((const uint8_t*)"hello", 5);
 *   int rc = scep_http_get_cacert("https://scep.example.com/...", &p7, &len,
 *                                 malloc, free);
 *   TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_OK, rc);
 *   free(p7);
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

/* ------------------------------------------------------------------ */
/* Enums / types that scep_transport.c expects                         */

typedef enum {
    HTTP_EVENT_ERROR = 0,
    HTTP_EVENT_ON_CONNECTED,
    HTTP_EVENT_HEADERS_SENT,
    HTTP_EVENT_HEADER_SENT = HTTP_EVENT_HEADERS_SENT,
    HTTP_EVENT_ON_HEADER,
    HTTP_EVENT_ON_DATA,
    HTTP_EVENT_ON_FINISH,
    HTTP_EVENT_DISCONNECTED,
    HTTP_EVENT_REDIRECT,
} esp_http_client_event_id_t;

typedef enum {
    HTTP_TRANSPORT_UNKNOWN = 0x0,
    HTTP_TRANSPORT_OVER_TCP,
    HTTP_TRANSPORT_OVER_SSL,
} esp_http_client_transport_t;

typedef enum {
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_NOTIFY,
    HTTP_METHOD_SUBSCRIBE,
    HTTP_METHOD_UNSUBSCRIBE,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_COPY,
    HTTP_METHOD_MOVE,
    HTTP_METHOD_LOCK,
    HTTP_METHOD_UNLOCK,
    HTTP_METHOD_PROPFIND,
    HTTP_METHOD_PROPPATCH,
    HTTP_METHOD_MKCOL,
    HTTP_METHOD_REPORT,
    HTTP_METHOD_MAX,
} esp_http_client_method_t;

/* Opaque handle */
typedef struct esp_http_client_stub *esp_http_client_handle_t;

struct esp_http_client_stub {
    int dummy;  /* opaque */
};

/* Forward declarations for the event type */
typedef struct esp_http_client_event esp_http_client_event_t;
typedef esp_err_t (*http_event_handle_cb)(esp_http_client_event_t *evt);

struct esp_http_client_event {
    esp_http_client_event_id_t event_id;
    esp_http_client_handle_t   client;
    void                      *data;
    int                        data_len;
    void                      *user_data;
    char                      *header_key;
    char                      *header_value;
};

/* Config struct: only the fields scep_transport.c actually uses */
typedef struct {
    const char                 *url;
    esp_http_client_method_t    method;
    http_event_handle_cb        event_handler;
    void                       *user_data;
    int                         timeout_ms;
    int                         buffer_size;
    int                         buffer_size_tx;
    const char                 *cert_pem;
    int                         cert_len;
    int                         skip_cert_common_name_check;
    esp_http_client_transport_t transport_type;
} esp_http_client_config_t;

/* ------------------------------------------------------------------ */
/* Stub control API (call from test code, not from production code)    */

/* Reset all stub state to "no response, init returns NULL" defaults. */
void esp_http_client_stub_reset(void);

/* If set to 0, esp_http_client_init returns NULL (simulates alloc fail). */
void esp_http_client_stub_set_init_succeeds(int succeeds);

/* Return value for esp_http_client_perform. */
void esp_http_client_stub_set_perform_result(esp_err_t result);

/* HTTP status code returned by esp_http_client_get_status_code. */
void esp_http_client_stub_set_status_code(int code);

/* Body data that will be injected into the event handler as HTTP_EVENT_ON_DATA. */
void esp_http_client_stub_set_response_body(const uint8_t *data, size_t len);

/* Return value for esp_http_client_set_header (default ESP_OK). */
void esp_http_client_stub_set_header_result(esp_err_t result);

/* Return value for esp_http_client_set_post_field (default ESP_OK). */
void esp_http_client_stub_set_post_field_result(esp_err_t result);

/* Retrieve the URL that was passed to esp_http_client_init. */
const char *esp_http_client_stub_get_last_url(void);

/* Retrieve the method that was passed to esp_http_client_init. */
esp_http_client_method_t esp_http_client_stub_get_last_method(void);

/* ------------------------------------------------------------------ */
/* ESP-IDF API surface (implemented in esp_http_client_stub.c)         */

esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *config);
esp_err_t esp_http_client_perform(esp_http_client_handle_t client);
esp_err_t esp_http_client_set_header(esp_http_client_handle_t client, const char *key, const char *value);
esp_err_t esp_http_client_set_post_field(esp_http_client_handle_t client, const char *data, int len);
int       esp_http_client_get_status_code(esp_http_client_handle_t client);
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client);
