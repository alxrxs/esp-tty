/*
 * ssh_server.h -- wolfSSH server session lifecycle for esp-tty
 *
 * Listens on TCP/SSH_PORT.  Accepts one session at a time; a new connection
 * cleanly tears down the active session and takes over (single-session
 * takeover policy).
 *
 * When a session is established, the server bridges data between the SSH
 * channel and two ring buffers:
 *
 *   SSH channel RX -> ssh_to_usb ring  (SSH client -> Linux host)
 *   usb_to_ssh ring -> SSH channel TX  (Linux host -> SSH client)
 */

#pragma once

#include "esp_err.h"
#include "ring.h"
#include "scrollback.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Start the SSH server FreeRTOS task.  The task listens on TCP/SSH_PORT,
 * authenticates clients (pubkey only), and pumps data through the rings.
 *
 * usb_to_ssh: ring that carries bytes from the Linux host toward the client
 * ssh_to_usb: ring that carries bytes from the client toward the Linux host
 *
 * Requires: wifi_init_sta() succeeded, host_key loaded into a wolfSSH CTX.
 * This function creates a wolfSSH context internally and calls
 * host_key_load_or_generate() to populate it.
 */
esp_err_t ssh_server_start(ring_t *usb_to_ssh, ring_t *ssh_to_usb,
                           scrollback_t *scrollback);

#ifdef __cplusplus
}
#endif
