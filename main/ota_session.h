/*
 * ota_session.h — OTA firmware update over SSH channel for esp-tty
 *
 * When a client authenticates as user "ota", the SSH server routes the
 * session here instead of the bridge pump.
 *
 * Protocol:
 *   Client streams a signed+encrypted OTA image (produced by
 *   scripts/sign_firmware.py) over the SSH channel's exec or shell channel.
 *   On success, the device sends "OTA_OK\n" and reboots.
 *   On failure, the device sends "OTA_ERR: <reason>\n" and closes without
 *   rebooting, leaving the current firmware running.
 */

#pragma once

#include "esp_err.h"
#include "wolfssh/ssh.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ota_session_handler — handle a fully authenticated OTA SSH session.
 *
 * ssh       : accepted wolfSSH session (wolfSSH_accept already returned WS_SUCCESS)
 * image_len : total length of the OTA image in bytes, announced by the client
 *             via the channel's environment variable OTA_IMAGE_LEN.
 *             If 0, the handler reads until EOF and determines length on the fly.
 *
 * The function reads the OTA image from the SSH channel, feeds it into
 * ota_verify, and on success marks the new partition bootable and reboots.
 * On failure, sends an error message and returns ESP_FAIL (no reboot).
 *
 * Caller must NOT call wolfSSH_free() while this is running.
 * This function closes the SSH channel and frees resources before returning.
 */
esp_err_t ota_session_handler(WOLFSSH *ssh);

#ifdef __cplusplus
}
#endif
