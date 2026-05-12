/*
 * rollback_decision.c -- pure rollback decision logic
 */

#include "rollback_decision.h"

rollback_decision_t rollback_decide(esp_ota_img_states_t state)
{
    if (state == ESP_OTA_IMG_PENDING_VERIFY)
        return ROLLBACK_DECISION_MARK_VALID;
    return ROLLBACK_DECISION_NOOP;
}
