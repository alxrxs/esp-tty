/*
 * rollback_decision.h -- pure rollback decision logic, testable natively.
 *
 * Extracted from main.c rollback_timer_cb so it can be unit-tested without
 * an ESP-IDF or FreeRTOS environment.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * On-device builds: use the real ESP-IDF OTA types.
 * Native test builds: use local stubs (same enum values as ESP-IDF).
 */
#ifndef ROLLBACK_DECISION_NATIVE_TEST
#include "esp_ota_ops.h"
#else
/* Minimal stub matching ESP-IDF esp_ota_img_states_t */
typedef enum {
    ESP_OTA_IMG_NEW             = 0x0,
    ESP_OTA_IMG_PENDING_VERIFY  = 0x1,
    ESP_OTA_IMG_VALID           = 0x2,
    ESP_OTA_IMG_INVALID         = 0x3,
    ESP_OTA_IMG_ABORTED         = 0x4,
    ESP_OTA_IMG_UNDEFINED       = 0xFFFFFFFF,
} esp_ota_img_states_t;
#endif

typedef enum {
    ROLLBACK_DECISION_MARK_VALID,  /* call esp_ota_mark_app_valid_cancel_rollback */
    ROLLBACK_DECISION_NOOP,        /* already valid or factory -- nothing to do */
} rollback_decision_t;

/*
 * rollback_decide -- pure decision function.
 *
 * Returns ROLLBACK_DECISION_MARK_VALID only when state is
 * ESP_OTA_IMG_PENDING_VERIFY; returns ROLLBACK_DECISION_NOOP otherwise.
 * No side effects -- safe to unit test.
 */
rollback_decision_t rollback_decide(esp_ota_img_states_t state);

#ifdef __cplusplus
}
#endif
