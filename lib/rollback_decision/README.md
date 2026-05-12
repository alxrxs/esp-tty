# lib/rollback_decision — OTA rollback decision logic

This module contains a single pure function, `rollback_decide(state)`, that maps
an `esp_ota_img_states_t` value to one of two outcomes: `ROLLBACK_DECISION_MARK_VALID`
or `ROLLBACK_DECISION_NOOP`. The function returns `ROLLBACK_DECISION_MARK_VALID` only
when `state == ESP_OTA_IMG_PENDING_VERIFY` and `ROLLBACK_DECISION_NOOP` for every
other state — `ESP_OTA_IMG_VALID`, `ESP_OTA_IMG_NEW`, `ESP_OTA_IMG_INVALID`,
`ESP_OTA_IMG_ABORTED`, and `ESP_OTA_IMG_UNDEFINED`. It has no side effects and
touches no globals.

## Role in the OTA rollback flow

ESP-IDF's application rollback feature marks a freshly booted OTA image as
`ESP_OTA_IMG_PENDING_VERIFY`. If the application crashes or the watchdog fires
before calling `esp_ota_mark_app_valid_cancel_rollback()`, the bootloader
automatically reverts to the previous image on the next reset. In `main.c` a
one-shot FreeRTOS software timer (`OTA_ROLLBACK_DELAY_MS`, default 30 s) fires
after the SSH server has been running without incident. Its callback,
`rollback_timer_cb`, reads the current OTA partition state via
`esp_ota_get_state_partition`, feeds it to `rollback_decide`, and calls
`esp_ota_mark_app_valid_cancel_rollback` only when the function returns
`ROLLBACK_DECISION_MARK_VALID`. For factory images or images that were already
marked valid the function returns `ROLLBACK_DECISION_NOOP` and the callback exits
without touching the OTA state.

## Files and native testability

- **rollback_decision.h** — declares `rollback_decision_t` and the
  `rollback_decide()` signature. On-device builds include the real
  `esp_ota_ops.h` for the `esp_ota_img_states_t` enum. When
  `ROLLBACK_DECISION_NATIVE_TEST` is defined the header instead supplies a
  minimal inline enum with the same numeric values as ESP-IDF, eliminating any
  dependency on the SDK headers.
- **rollback_decision.c** — implementation (one `if` statement; no platform
  calls).

The library was extracted from `main.c` specifically to make the decision
testable on the host. `test/native/test_rollback_decision/test_rollback_decision.c`
covers all six `esp_ota_img_states_t` variants using Unity, compiled with
`-DROLLBACK_DECISION_NATIVE_TEST`.
