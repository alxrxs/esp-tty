/*
 * rollback_decision.c -- pure rollback decision logic
 */

#include "rollback_decision.h"

rollback_decision_t rollback_decide(esp_ota_img_states_t state)
{
    if (state == ESP_OTA_IMG_PENDING_VERIFY)
        return ROLLBACK_DECISION_MARK_VALID;

    if (state == ESP_OTA_IMG_NEW)
        /* Defensive -- handles factory images (never OTA'd, no otadata) where
         * ESP-IDF returns NEW instead of PENDING_VERIFY.  With
         * CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y the bootloader transitions
         * NEW -> PENDING_VERIFY before handing control to the app, so this
         * branch is NOT the normal OTA path; it is a safety net for the
         * factory-flashed slot where otadata has never been written.
         * Calling esp_ota_mark_app_valid_cancel_rollback() on an already-valid
         * factory image is documented as a no-op per the ESP-IDF API docs for
         * that function, so this is safe to call unconditionally. */
        return ROLLBACK_DECISION_MARK_VALID;

    /* ABORTED means a prior OTA write was interrupted before the new image
     * was fully written and committed.  The slot is unusable; the bootloader
     * will not boot it again.  There is nothing to mark valid here -- the
     * currently-running image (in the other slot) was already marked valid
     * by a previous boot.  NOOP is correct. */
    return ROLLBACK_DECISION_NOOP;
}
