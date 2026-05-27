/*
 * host_key.h -- ED25519 SSH host key: generate-or-load from NVS
 *
 * On first boot, generates a fresh ED25519 key via wolfCrypt + ESP32
 * hardware RNG and persists it to NVS.  On subsequent boots, loads the
 * stored key.  Prints the SHA-256 fingerprint (base64) to the UART log
 * so the user can verify it on the first SSH connection.
 *
 * Reset: `idf.py erase-flash` wipes NVS -> next boot generates a fresh key.
 * No eFuses are burned.
 *
 * Extension point for DS peripheral / eFuse-backed storage:
 *   Replace the nvs_set_blob / nvs_get_blob calls in host_key.c with
 *   DS peripheral APIs -- no other changes required.
 */

#pragma once

#include <stdint.h>
#include "esp_err.h"
#include "wolfssh/ssh.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Load the ED25519 host key from NVS, or generate and persist one if not
 * found.  Loads the DER-encoded key into ctx via
 * wolfSSH_CTX_UsePrivateKey_buffer().
 *
 * Prerequisites:
 *   - nvs_flash_init() (or nvs_flash_secure_init()) must have been called.
 *   - wolfSSH_Init() and wolfSSH_CTX_new() must have been called; ctx must
 *     be a valid server context.
 *
 * Entropy:
 *   The first-time generation path internally gates the HW RNG via
 *   bootloader_random_enable() so it does NOT depend on the Wi-Fi/BT radio
 *   being started.  The radio path still seeds esp_random when up; the
 *   bootloader source is an additional analog-noise source used as a
 *   belt-and-braces defence (see host_key.c:entropy_gate_engage for the
 *   ESP-IDF doc reference).  Caller does not need to start the radio first.
 *
 * NVS resilience:
 *   ANY error from the NVS read path (not just ESP_ERR_NVS_NOT_FOUND) is
 *   treated as "no key on disk" and triggers regeneration.  This avoids a
 *   boot loop when NVS is mildly corrupted (e.g. ESP_ERR_NVS_INVALID_HANDLE,
 *   partial-erase encryption mismatch).  If the regenerated key cannot be
 *   persisted (nvs_save_key returns non-OK), this function falls back to an
 *   in-memory-only ("ephemeral") key for the current boot so the device
 *   remains reachable over SSH for diagnostics; the SSH fingerprint will
 *   then change on every reboot until NVS is recovered.
 *
 *   The function returns ESP_OK whenever a usable key (persisted OR
 *   ephemeral) has been loaded into ctx.  It returns non-OK only when
 *   keygen itself is impossible (e.g. wolfCrypt RNG init failure).
 *
 * Returns ESP_OK on success (key persisted or ephemeral, ctx loaded).
 */
esp_err_t host_key_load_or_generate(WOLFSSH_CTX *ctx);

#ifdef __cplusplus
}
#endif
