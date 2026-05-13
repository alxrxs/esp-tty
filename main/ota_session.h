/*
 * ota_session.h -- OTA firmware update over SSH channel for esp-tty
 *
 * Routed from ssh_server.c when the SSH username is "ota".  The SSH layer
 * already authenticates the client against OTA_AUTHORIZED_PUBKEY.  This
 * handler performs an inner X25519 key exchange + AES-256-GCM encrypted
 * firmware transfer (see ota_session.c for the wire protocol).
 *
 * On success the device sends 0x00, closes the channel, and reboots into
 * the freshly written OTA slot.  On failure it sends 0xFF + reason and
 * returns ESP_FAIL without rebooting.
 */

#pragma once

#include "esp_err.h"
#include "wolfssh/ssh.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t ota_session_handler(WOLFSSH *ssh);

#ifdef __cplusplus
}
#endif
