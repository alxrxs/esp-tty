/*
 * host_key.h — ED25519 SSH host key: generate-or-load from NVS
 *
 * On first boot, generates a fresh ED25519 key via wolfCrypt + ESP32
 * hardware RNG and persists it to NVS.  On subsequent boots, loads the
 * stored key.  Prints the SHA-256 fingerprint (base64) to the UART log
 * so the user can verify it on the first SSH connection.
 *
 * Reset: `idf.py erase-flash` wipes NVS → next boot generates a fresh key.
 * No eFuses are burned.
 *
 * Extension point for DS peripheral / eFuse-backed storage:
 *   Replace the nvs_set_blob / nvs_get_blob calls in host_key.c with
 *   DS peripheral APIs — no other changes required.
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
 *   - Wi-Fi (or BT) must be started before this call so the hardware RNG
 *     has sufficient entropy for key generation.
 *   - wolfSSH_Init() and wolfSSH_CTX_new() must have been called; ctx must
 *     be a valid server context.
 *
 * Returns ESP_OK on success.
 */
esp_err_t host_key_load_or_generate(WOLFSSH_CTX *ctx);

#ifdef __cplusplus
}
#endif
