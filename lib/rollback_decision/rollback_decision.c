/*
 * rollback_decision.c -- pure rollback decision logic
 */

#include "rollback_decision.h"

rollback_decision_t rollback_decide(esp_ota_img_states_t state)
{
    if (state == ESP_OTA_IMG_PENDING_VERIFY)
        return ROLLBACK_DECISION_MARK_VALID;

    if (state == ESP_OTA_IMG_NEW)
        /* NEW means the bootloader has not yet run the app's mark-valid
         * handshake.  If rollback is enabled and the app crashes before
         * calling esp_ota_mark_app_valid_cancel_rollback(), the bootloader
         * will roll back to the previous slot.  Treat NEW the same as
         * PENDING_VERIFY so the app marks itself valid immediately on
         * successful startup. */
        return ROLLBACK_DECISION_MARK_VALID;

    /* ABORTED means a prior OTA write was interrupted before the new image
     * was fully written and committed.  The slot is unusable; the bootloader
     * will not boot it again.  There is nothing to mark valid here -- the
     * currently-running image (in the other slot) was already marked valid
     * by a previous boot.  NOOP is correct. */
    return ROLLBACK_DECISION_NOOP;
}
