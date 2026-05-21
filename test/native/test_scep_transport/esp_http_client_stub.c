/*
 * esp_http_client_stub.c -- programmable fake for ESP-IDF HTTP client.
 *
 * Implements the stub control API declared in test/stubs/esp_http_client.h
 * plus the actual ESP-IDF API surface called by lib/scep_transport/scep_transport.c.
 *
 * Compiled only into the native test binary for test_scep_transport; never
 * compiled into firmware.
 */

#define SCEP_CA_PEM_EMBEDDED    1   /* suppress extern asm() in scep_transport.h */
#define SCEP_TRANSPORT_NATIVE_TEST 1

#include "esp_http_client.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Stub for the embedded CA cert symbols that scep_transport.c references */

const uint8_t scep_ca_pem_start[] = { 0 };  /* empty PEM -- ignored by stub */
const uint8_t scep_ca_pem_end[]   = { 0 };

/* ------------------------------------------------------------------ */
/* Global stub state                                                    */

static int                      s_init_succeeds     = 1;
static esp_err_t                s_perform_result    = ESP_OK;
static int                      s_status_code       = 200;
static esp_err_t                s_header_result     = ESP_OK;
static esp_err_t                s_post_field_result = ESP_OK;

#define MAX_RESP_BODY  (256 * 1024)
static uint8_t  s_resp_body[MAX_RESP_BODY];
static size_t   s_resp_len = 0;

/* The config captured on the last call to esp_http_client_init */
static char                           s_last_url[512];
static esp_http_client_method_t       s_last_method;
static http_event_handle_cb           s_captured_handler = NULL;
static void                          *s_captured_user_data = NULL;

/* One static handle instance */
static struct esp_http_client_stub s_handle_instance;

/* ------------------------------------------------------------------ */
/* Stub control API                                                     */

void esp_http_client_stub_reset(void)
{
    s_init_succeeds     = 1;
    s_perform_result    = ESP_OK;
    s_status_code       = 200;
    s_header_result     = ESP_OK;
    s_post_field_result = ESP_OK;
    s_resp_len          = 0;
    s_last_url[0]       = '\0';
    s_last_method       = HTTP_METHOD_GET;
    s_captured_handler  = NULL;
    s_captured_user_data = NULL;
}

void esp_http_client_stub_set_init_succeeds(int succeeds)
{
    s_init_succeeds = succeeds;
}

void esp_http_client_stub_set_perform_result(esp_err_t result)
{
    s_perform_result = result;
}

void esp_http_client_stub_set_status_code(int code)
{
    s_status_code = code;
}

void esp_http_client_stub_set_response_body(const uint8_t *data, size_t len)
{
    if (len > MAX_RESP_BODY) len = MAX_RESP_BODY;
    memcpy(s_resp_body, data, len);
    s_resp_len = len;
}

void esp_http_client_stub_set_header_result(esp_err_t result)
{
    s_header_result = result;
}

void esp_http_client_stub_set_post_field_result(esp_err_t result)
{
    s_post_field_result = result;
}

const char *esp_http_client_stub_get_last_url(void)
{
    return s_last_url;
}

esp_http_client_method_t esp_http_client_stub_get_last_method(void)
{
    return s_last_method;
}

/* ------------------------------------------------------------------ */
/* ESP-IDF API implementation                                           */

esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *config)
{
    if (!s_init_succeeds) return NULL;

    if (config) {
        if (config->url) {
            strncpy(s_last_url, config->url, sizeof(s_last_url) - 1);
            s_last_url[sizeof(s_last_url) - 1] = '\0';
        }
        s_last_method        = config->method;
        s_captured_handler   = config->event_handler;
        s_captured_user_data = config->user_data;
    }
    return &s_handle_instance;
}

esp_err_t esp_http_client_perform(esp_http_client_handle_t client)
{
    (void)client;
    if (s_perform_result != ESP_OK) return s_perform_result;

    /* Inject the response body as HTTP_EVENT_ON_DATA events */
    if (s_captured_handler && s_resp_len > 0) {
        esp_http_client_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id  = HTTP_EVENT_ON_DATA;
        evt.client    = &s_handle_instance;
        evt.data      = s_resp_body;
        evt.data_len  = (int)s_resp_len;
        evt.user_data = s_captured_user_data;
        s_captured_handler(&evt);
    }
    return ESP_OK;
}

esp_err_t esp_http_client_set_header(esp_http_client_handle_t client,
                                     const char *key, const char *value)
{
    (void)client; (void)key; (void)value;
    return s_header_result;
}

esp_err_t esp_http_client_set_post_field(esp_http_client_handle_t client,
                                         const char *data, int len)
{
    (void)client; (void)data; (void)len;
    return s_post_field_result;
}

int esp_http_client_get_status_code(esp_http_client_handle_t client)
{
    (void)client;
    return s_status_code;
}

esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client)
{
    (void)client;
    return ESP_OK;
}
