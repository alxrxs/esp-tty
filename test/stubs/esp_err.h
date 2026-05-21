#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
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

static inline const char *esp_err_to_name(esp_err_t err)
{
    switch (err) {
    case ESP_OK:               return "ESP_OK";
    case ESP_FAIL:             return "ESP_FAIL";
    case 0x101:                return "ESP_ERR_NO_MEM";
    case 0x102:                return "ESP_ERR_INVALID_ARG";
    case 0x103:                return "ESP_ERR_INVALID_STATE";
    case 0x1102:               return "ESP_ERR_NVS_NOT_FOUND";
    default:                   return "ESP_ERR_UNKNOWN";
    }
}
