/*
 * test_scep_transport.c -- native unit tests for lib/scep_transport/scep_transport.c
 *
 * Uses the programmable esp_http_client stub defined in esp_http_client_stub.c.
 * No real network connection is made; the stub injects canned responses.
 *
 * Coverage:
 *
 * Input-validation paths (before any HTTP call):
 *   1.  scep_http_get_cacert: NULL base_url returns SCEP_TRANSPORT_ERR_INVALID_ARG
 *   2.  scep_http_get_cacert: NULL out_p7 returns SCEP_TRANSPORT_ERR_INVALID_ARG
 *   3.  scep_http_get_cacert: NULL out_len returns SCEP_TRANSPORT_ERR_INVALID_ARG
 *   4.  scep_http_get_cacert: NULL alloc returns SCEP_TRANSPORT_ERR_INVALID_ARG
 *   5.  scep_http_get_cacert: NULL free_ returns SCEP_TRANSPORT_ERR_INVALID_ARG
 *   6.  scep_http_get_cacert: URL exactly at limit passes
 *   7.  scep_http_get_cacert: URL over limit returns SCEP_TRANSPORT_ERR_URL_TOO_LONG
 *   8.  scep_http_pkioperation: NULL base_url returns INVALID_ARG
 *   9.  scep_http_pkioperation: NULL p7_in returns INVALID_ARG
 *  10.  scep_http_pkioperation: p7_in_len==0 returns INVALID_ARG
 *  11.  scep_http_pkioperation: NULL out_p7 returns INVALID_ARG
 *  12.  scep_http_pkioperation: NULL out_len returns INVALID_ARG
 *  13.  scep_http_pkioperation: URL over limit returns URL_TOO_LONG
 *
 * Happy-path stub calls:
 *  14.  GetCACert success: returns OK, body forwarded, caller must free
 *  15.  PKIOperation success: returns OK, method is POST, body forwarded
 *  16.  GetCACert builds correct URL (?operation=GetCACert suffix)
 *  17.  PKIOperation builds correct URL (?operation=PKIOperation suffix)
 *
 * Error paths with stub control:
 *  18.  esp_http_client_init returns NULL -> SCEP_TRANSPORT_ERR_HTTP
 *  19.  esp_http_client_perform returns error -> SCEP_TRANSPORT_ERR_HTTP
 *  20.  HTTP status != 200 -> SCEP_TRANSPORT_ERR_HTTP_STATUS
 *  21.  HTTP 200 but empty body -> SCEP_TRANSPORT_ERR_EMPTY_BODY
 *  22.  set_header failure (POST) -> SCEP_TRANSPORT_ERR_HTTP
 *  23.  set_post_field failure (POST) -> SCEP_TRANSPORT_ERR_HTTP
 *
 * Response buffer growth:
 *  24.  Large response (>8 KB, forces buffer doubling) is fully returned
 */

#define SCEP_CA_PEM_EMBEDDED    1
#define SCEP_TRANSPORT_NATIVE_TEST 1

#include "unity.h"
#include "scep_transport.h"
#include "esp_http_client.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Stub control functions declared in esp_http_client_stub.c */
void esp_http_client_stub_reset(void);
void esp_http_client_stub_set_init_succeeds(int succeeds);
void esp_http_client_stub_set_perform_result(esp_err_t result);
void esp_http_client_stub_set_status_code(int code);
void esp_http_client_stub_set_response_body(const uint8_t *data, size_t len);
void esp_http_client_stub_set_header_result(esp_err_t result);
void esp_http_client_stub_set_post_field_result(esp_err_t result);
const char *esp_http_client_stub_get_last_url(void);
esp_http_client_method_t esp_http_client_stub_get_last_method(void);

/* ------------------------------------------------------------------ */
/* Constants mirrored from scep_transport.c                            */
#define SCEP_URL_MAX_TRANSPORT  512   /* internal limit in scep_transport.c */

void setUp(void)    { esp_http_client_stub_reset(); }
void tearDown(void) {}

/* ================================================================== */
/* Section 1: Input validation for scep_http_get_cacert               */
/* ================================================================== */

void test_get_cacert_null_url_returns_invalid_arg(void)
{
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert(NULL, &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
    TEST_ASSERT_NULL(p7);
}

void test_get_cacert_null_out_p7_returns_invalid_arg(void)
{
    size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", NULL, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_get_cacert_null_out_len_returns_invalid_arg(void)
{
    uint8_t *p7 = NULL;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, NULL, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
    TEST_ASSERT_NULL(p7);
}

void test_get_cacert_null_alloc_returns_invalid_arg(void)
{
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, NULL, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_get_cacert_null_free_returns_invalid_arg(void)
{
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, NULL);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

/* Build a base_url such that base_url + "?operation=GetCACert" is exactly
 * SCEP_URL_MAX_TRANSPORT - 1 chars (not counting the NUL).  This should succeed. */
void test_get_cacert_url_at_limit_passes(void)
{
    /* "?operation=GetCACert" is 20 chars; NUL makes the buffer size 512.
     * So base_url must be 512 - 20 - 1 = 491 chars. */
    const size_t op_suffix = strlen("?operation=GetCACert");
    const size_t limit = SCEP_URL_MAX_TRANSPORT - 1;
    const size_t base_max = limit - op_suffix;  /* 491 */

    char base_url[600];
    memset(base_url, 'x', base_max);
    base_url[base_max] = '\0';

    /* Set up stub for a minimal success response */
    static const uint8_t body[] = { 0x30, 0x03, 0x01, 0x01, 0x00 };
    esp_http_client_stub_set_response_body(body, sizeof(body));

    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert(base_url, &p7, &len, malloc, free);
    /* Should NOT return URL_TOO_LONG; it may return OK or another error */
    TEST_ASSERT_NOT_EQUAL(SCEP_TRANSPORT_ERR_URL_TOO_LONG, rc);
    if (p7) free(p7);
}

/* One byte over the limit -> URL_TOO_LONG */
void test_get_cacert_url_over_limit_returns_url_too_long(void)
{
    const size_t op_suffix = strlen("?operation=GetCACert");
    const size_t limit = SCEP_URL_MAX_TRANSPORT - 1;
    const size_t over = limit - op_suffix + 1;  /* 492 -- one too many */

    char *base_url = (char *)malloc(over + 1);
    TEST_ASSERT_NOT_NULL(base_url);
    memset(base_url, 'x', over);
    base_url[over] = '\0';

    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert(base_url, &p7, &len, malloc, free);
    free(base_url);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_URL_TOO_LONG, rc);
    TEST_ASSERT_NULL(p7);
}

/* ================================================================== */
/* Section 2: Input validation for scep_http_pkioperation             */
/* ================================================================== */

void test_pkiop_null_url_returns_invalid_arg(void)
{
    uint8_t dummy[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation(NULL, dummy, 4, &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_pkiop_null_p7in_returns_invalid_arg(void)
{
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/", NULL, 4, &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_pkiop_zero_len_returns_invalid_arg(void)
{
    uint8_t dummy[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/", dummy, 0, &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_pkiop_null_out_p7_returns_invalid_arg(void)
{
    uint8_t dummy[4] = {0}; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/", dummy, 4, NULL, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_pkiop_null_out_len_returns_invalid_arg(void)
{
    uint8_t dummy[4] = {0}; uint8_t *p7 = NULL;
    int rc = scep_http_pkioperation("https://scep.example.com/", dummy, 4, &p7, NULL, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

void test_pkiop_url_over_limit_returns_url_too_long(void)
{
    const size_t op_suffix = strlen("?operation=PKIOperation");
    const size_t limit = SCEP_URL_MAX_TRANSPORT - 1;
    const size_t over = limit - op_suffix + 1;

    char *base_url = (char *)malloc(over + 1);
    TEST_ASSERT_NOT_NULL(base_url);
    memset(base_url, 'x', over);
    base_url[over] = '\0';

    uint8_t dummy[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation(base_url, dummy, 4, &p7, &len, malloc, free);
    free(base_url);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_URL_TOO_LONG, rc);
}

/* ================================================================== */
/* Section 3: Happy-path stub calls                                    */
/* ================================================================== */

void test_get_cacert_success_body_returned(void)
{
    static const uint8_t body[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    esp_http_client_stub_set_response_body(body, sizeof(body));

    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/mscep",
                                  &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_OK, rc);
    TEST_ASSERT_NOT_NULL(p7);
    TEST_ASSERT_EQUAL_size_t(sizeof(body), len);
    TEST_ASSERT_EQUAL_MEMORY(body, p7, sizeof(body));
    free(p7);
}

void test_pkiop_success_uses_post_method(void)
{
    static const uint8_t resp[] = { 0xAA, 0xBB };
    esp_http_client_stub_set_response_body(resp, sizeof(resp));

    uint8_t req[8] = { 0x30, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/mscep",
                                    req, sizeof(req),
                                    &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_OK, rc);
    TEST_ASSERT_NOT_NULL(p7);
    TEST_ASSERT_EQUAL_size_t(sizeof(resp), len);
    TEST_ASSERT_EQUAL_MEMORY(resp, p7, sizeof(resp));
    TEST_ASSERT_EQUAL_INT(HTTP_METHOD_POST, esp_http_client_stub_get_last_method());
    free(p7);
}

void test_get_cacert_url_has_correct_suffix(void)
{
    static const uint8_t body[] = { 0x01 };
    esp_http_client_stub_set_response_body(body, sizeof(body));

    const char *base = "https://scep.example.com/mscep";
    uint8_t *p7 = NULL; size_t len = 0;
    scep_http_get_cacert(base, &p7, &len, malloc, free);
    if (p7) free(p7);

    const char *url = esp_http_client_stub_get_last_url();
    /* URL must end with "?operation=GetCACert" */
    size_t ulen = strlen(url);
    const char *suffix = "?operation=GetCACert";
    size_t slen = strlen(suffix);
    TEST_ASSERT_GREATER_OR_EQUAL(slen, ulen);
    TEST_ASSERT_EQUAL_STRING_LEN(suffix, url + ulen - slen, slen);
}

void test_pkiop_url_has_correct_suffix(void)
{
    static const uint8_t resp[] = { 0x01 };
    esp_http_client_stub_set_response_body(resp, sizeof(resp));

    const char *base = "https://scep.example.com/mscep";
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    scep_http_pkioperation(base, in, sizeof(in), &p7, &len, malloc, free);
    if (p7) free(p7);

    const char *url = esp_http_client_stub_get_last_url();
    size_t ulen = strlen(url);
    const char *suffix = "?operation=PKIOperation";
    size_t slen = strlen(suffix);
    TEST_ASSERT_GREATER_OR_EQUAL(slen, ulen);
    TEST_ASSERT_EQUAL_STRING_LEN(suffix, url + ulen - slen, slen);
}

/* ================================================================== */
/* Section 4: Error paths via stub control                             */
/* ================================================================== */

void test_get_cacert_init_fails_returns_http_error(void)
{
    esp_http_client_stub_set_init_succeeds(0);
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP, rc);
    TEST_ASSERT_NULL(p7);
}

void test_get_cacert_perform_fails_returns_http_error(void)
{
    esp_http_client_stub_set_perform_result(ESP_FAIL);
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP, rc);
    TEST_ASSERT_NULL(p7);
}

void test_get_cacert_status_404_returns_http_status_error(void)
{
    static const uint8_t body[] = { 0x01 };
    esp_http_client_stub_set_response_body(body, sizeof(body));
    esp_http_client_stub_set_status_code(404);
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP_STATUS, rc);
    TEST_ASSERT_NULL(p7);
}

void test_get_cacert_empty_body_returns_empty_body_error(void)
{
    /* No body set => zero bytes injected => HTTP_EVENT_ON_DATA not called */
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_EMPTY_BODY, rc);
    TEST_ASSERT_NULL(p7);
}

void test_pkiop_set_header_fails_returns_http_error(void)
{
    esp_http_client_stub_set_header_result(ESP_FAIL);
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP, rc);
    TEST_ASSERT_NULL(p7);
}

void test_pkiop_set_post_field_fails_returns_http_error(void)
{
    esp_http_client_stub_set_post_field_result(ESP_FAIL);
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP, rc);
    TEST_ASSERT_NULL(p7);
}

/* ================================================================== */
/* Section 5: Large response body (forces resp_buf_append to grow)    */
/* ================================================================== */

void test_get_cacert_large_body_forces_buffer_growth(void)
{
    /* RESP_INIT_BYTES in scep_transport.c is 8 KiB.  Send 20 KiB to
     * exercise at least two doublings of the internal buffer. */
    const size_t large_len = 20 * 1024;
    uint8_t *large_body = (uint8_t *)malloc(large_len);
    TEST_ASSERT_NOT_NULL(large_body);

    for (size_t i = 0; i < large_len; i++)
        large_body[i] = (uint8_t)(i & 0xFF);

    esp_http_client_stub_set_response_body(large_body, large_len);

    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/",
                                  &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_OK, rc);
    TEST_ASSERT_NOT_NULL(p7);
    TEST_ASSERT_EQUAL_size_t(large_len, len);
    TEST_ASSERT_EQUAL_MEMORY(large_body, p7, large_len);

    free(large_body);
    free(p7);
}

/* ================================================================== */
/* Section 6: Additional error-path and boundary tests                 */
/* ================================================================== */

/* HTTP 500 -> SCEP_TRANSPORT_ERR_HTTP_STATUS */
void test_get_cacert_status_500_returns_http_status_error(void)
{
    static const uint8_t body[] = { 0x01 };
    esp_http_client_stub_set_response_body(body, sizeof(body));
    esp_http_client_stub_set_status_code(500);
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP_STATUS, rc);
    TEST_ASSERT_NULL(p7);
}

/* HTTP 302 (redirect) -> SCEP_TRANSPORT_ERR_HTTP_STATUS */
void test_get_cacert_status_302_returns_http_status_error(void)
{
    static const uint8_t body[] = { 0x01 };
    esp_http_client_stub_set_response_body(body, sizeof(body));
    esp_http_client_stub_set_status_code(302);
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP_STATUS, rc);
    TEST_ASSERT_NULL(p7);
}

/* HTTP 503 (service unavailable) -> SCEP_TRANSPORT_ERR_HTTP_STATUS */
void test_pkiop_status_503_returns_http_status_error(void)
{
    static const uint8_t body[] = { 0x01 };
    esp_http_client_stub_set_response_body(body, sizeof(body));
    esp_http_client_stub_set_status_code(503);
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP_STATUS, rc);
    TEST_ASSERT_NULL(p7);
}

/* HTTP 201 (Created) -> SCEP_TRANSPORT_ERR_HTTP_STATUS (SCEP only uses 200) */
void test_get_cacert_status_201_returns_http_status_error(void)
{
    static const uint8_t body[] = { 0x01 };
    esp_http_client_stub_set_response_body(body, sizeof(body));
    esp_http_client_stub_set_status_code(201);
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP_STATUS, rc);
    TEST_ASSERT_NULL(p7);
}

/* Empty body on PKIOperation -> SCEP_TRANSPORT_ERR_EMPTY_BODY */
void test_pkiop_empty_body_returns_empty_body_error(void)
{
    /* No response body set */
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_EMPTY_BODY, rc);
    TEST_ASSERT_NULL(p7);
}

/* PKIOperation init fails -> SCEP_TRANSPORT_ERR_HTTP */
void test_pkiop_init_fails_returns_http_error(void)
{
    esp_http_client_stub_set_init_succeeds(0);
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP, rc);
    TEST_ASSERT_NULL(p7);
}

/* PKIOperation perform fails -> SCEP_TRANSPORT_ERR_HTTP */
void test_pkiop_perform_fails_returns_http_error(void)
{
    esp_http_client_stub_set_perform_result(ESP_FAIL);
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_HTTP, rc);
    TEST_ASSERT_NULL(p7);
}

/* Exactly 1-byte response is returned correctly */
void test_get_cacert_one_byte_body_returned(void)
{
    static const uint8_t body[] = { 0x42 };
    esp_http_client_stub_set_response_body(body, sizeof(body));
    uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_get_cacert("https://scep.example.com/", &p7, &len, malloc, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_OK, rc);
    TEST_ASSERT_NOT_NULL(p7);
    TEST_ASSERT_EQUAL_size_t(1, len);
    TEST_ASSERT_EQUAL_HEX8(0x42, p7[0]);
    free(p7);
}

/* PKIOperation null alloc returns INVALID_ARG */
void test_pkiop_null_alloc_returns_invalid_arg(void)
{
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, NULL, free);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

/* PKIOperation null free returns INVALID_ARG */
void test_pkiop_null_free_returns_invalid_arg(void)
{
    uint8_t in[4] = {0}; uint8_t *p7 = NULL; size_t len = 0;
    int rc = scep_http_pkioperation("https://scep.example.com/",
                                    in, sizeof(in), &p7, &len, malloc, NULL);
    TEST_ASSERT_EQUAL_INT(SCEP_TRANSPORT_ERR_INVALID_ARG, rc);
}

/* ================================================================== */
/* Main                                                                */
/* ================================================================== */

int main(void)
{
    UNITY_BEGIN();

    /* GetCACert input validation */
    RUN_TEST(test_get_cacert_null_url_returns_invalid_arg);
    RUN_TEST(test_get_cacert_null_out_p7_returns_invalid_arg);
    RUN_TEST(test_get_cacert_null_out_len_returns_invalid_arg);
    RUN_TEST(test_get_cacert_null_alloc_returns_invalid_arg);
    RUN_TEST(test_get_cacert_null_free_returns_invalid_arg);
    RUN_TEST(test_get_cacert_url_at_limit_passes);
    RUN_TEST(test_get_cacert_url_over_limit_returns_url_too_long);

    /* PKIOperation input validation */
    RUN_TEST(test_pkiop_null_url_returns_invalid_arg);
    RUN_TEST(test_pkiop_null_p7in_returns_invalid_arg);
    RUN_TEST(test_pkiop_zero_len_returns_invalid_arg);
    RUN_TEST(test_pkiop_null_out_p7_returns_invalid_arg);
    RUN_TEST(test_pkiop_null_out_len_returns_invalid_arg);
    RUN_TEST(test_pkiop_url_over_limit_returns_url_too_long);

    /* Happy paths */
    RUN_TEST(test_get_cacert_success_body_returned);
    RUN_TEST(test_pkiop_success_uses_post_method);
    RUN_TEST(test_get_cacert_url_has_correct_suffix);
    RUN_TEST(test_pkiop_url_has_correct_suffix);

    /* Error paths */
    RUN_TEST(test_get_cacert_init_fails_returns_http_error);
    RUN_TEST(test_get_cacert_perform_fails_returns_http_error);
    RUN_TEST(test_get_cacert_status_404_returns_http_status_error);
    RUN_TEST(test_get_cacert_empty_body_returns_empty_body_error);
    RUN_TEST(test_pkiop_set_header_fails_returns_http_error);
    RUN_TEST(test_pkiop_set_post_field_fails_returns_http_error);

    /* Large response body */
    RUN_TEST(test_get_cacert_large_body_forces_buffer_growth);

    /* Additional HTTP status code coverage */
    RUN_TEST(test_get_cacert_status_500_returns_http_status_error);
    RUN_TEST(test_get_cacert_status_302_returns_http_status_error);
    RUN_TEST(test_pkiop_status_503_returns_http_status_error);
    RUN_TEST(test_get_cacert_status_201_returns_http_status_error);
    RUN_TEST(test_pkiop_empty_body_returns_empty_body_error);
    RUN_TEST(test_pkiop_init_fails_returns_http_error);
    RUN_TEST(test_pkiop_perform_fails_returns_http_error);
    RUN_TEST(test_get_cacert_one_byte_body_returned);
    RUN_TEST(test_pkiop_null_alloc_returns_invalid_arg);
    RUN_TEST(test_pkiop_null_free_returns_invalid_arg);

    return UNITY_END();
}
