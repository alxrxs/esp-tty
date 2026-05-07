#pragma once
#include <stdint.h>
#include <stdio.h>
typedef int32_t esp_err_t;
#define ESP_OK    0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERROR_CHECK(x) do { \
    esp_err_t _e = (x); \
    if (_e != ESP_OK) { fprintf(stderr, "ESP_ERROR_CHECK failed: %d\n", _e); abort(); } \
} while(0)
