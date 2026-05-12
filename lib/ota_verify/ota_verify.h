/*
 * ota_verify.h -- streaming OTA image verifier / decryptor for esp-tty
 *
 * Image format (produced by scripts/sign_firmware.py):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *        0     8  magic = "ESPOTA1\0"
 *        8     4  version (LE uint32, currently 1)
 *       12     4  plaintext_len (LE uint32, original firmware size)
 *       16    12  AES-256-GCM IV (random, 12 bytes)
 *       28    16  AES-256-GCM tag (authentication tag)
 *       44     N  ciphertext (AES-256-GCM encrypted firmware)
 *     44+N    64  ECDSA-P256 signature (raw r||s, 32+32 bytes) over
 *                 SHA-256(magic..end-of-ciphertext)
 *
 * Security model (approach (b) from design spec):
 *   1. Stream ciphertext into OTA partition while incrementally computing
 *      SHA-256 over the signed region (header + ciphertext).
 *   2. After all ciphertext bytes are received, verify the 64-byte ECDSA
 *      signature over that SHA-256 digest.
 *   3. Only call esp_ota_set_boot_partition() if ECDSA verify succeeds.
 *   4. AES-GCM authentication tag is verified during decrypt; if it fails
 *      the session is aborted and the partition is left untouched (or
 *      partially written -- but bootloader will not select it because step 3
 *      did not run).
 *
 * Thread safety: each ota_verify_ctx_t must be used from a single task.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -- Error codes ----------------------------------------------------------- */

typedef enum {
    OTA_VERIFY_OK            = 0,
    OTA_VERIFY_ERR_MAGIC     = -1,  /* bad magic bytes         */
    OTA_VERIFY_ERR_VERSION   = -2,  /* unsupported version     */
    OTA_VERIFY_ERR_TRUNCATED = -3,  /* image shorter than expected */
    OTA_VERIFY_ERR_SIG       = -4,  /* ECDSA signature bad     */
    OTA_VERIFY_ERR_TAG       = -5,  /* AES-GCM tag mismatch    */
    OTA_VERIFY_ERR_FLASH     = -6,  /* flash write error        */
    OTA_VERIFY_ERR_OOM       = -7,  /* memory allocation error  */
    OTA_VERIFY_ERR_CRYPTO    = -8,  /* mbedtls internal error   */
    OTA_VERIFY_ERR_PARAM          = -9,  /* bad parameter            */
    OTA_VERIFY_ERR_LENGTH_MISMATCH = -10, /* plaintext_len != actual ciphertext received */
    OTA_VERIFY_ERR_EMPTY_IMAGE    = -11, /* plaintext_len == 0 -- refusing empty firmware */
} ota_verify_err_t;

/* -- Header constants ------------------------------------------------------ */

#define OTA_MAGIC           "ESPOTA1\0"
#define OTA_MAGIC_LEN       8
#define OTA_VERSION         1
#define OTA_IV_LEN          12
#define OTA_TAG_LEN         16
#define OTA_SIG_LEN         64
#define OTA_HEADER_SIZE     (OTA_MAGIC_LEN + 4 + 4 + OTA_IV_LEN + OTA_TAG_LEN)  /* 44 */

/* -- Streaming context ----------------------------------------------------- */

/* Opaque context -- implementation in ota_verify.c */
typedef struct ota_verify_ctx ota_verify_ctx_t;

/*
 * ota_verify_begin -- initialise a streaming verification session.
 *
 * pub_key_pem      : ECDSA-P256 public key in PEM format (NUL-terminated)
 * pub_key_pem_len  : length including the NUL terminator
 * aes_key          : 32-byte AES-256 raw key
 *
 * Returns a heap-allocated context on success, NULL on allocation failure.
 * The caller must call ota_verify_end() or ota_verify_abort() in all paths.
 */
ota_verify_ctx_t *ota_verify_begin(const uint8_t *pub_key_pem,
                                   size_t         pub_key_pem_len,
                                   const uint8_t  aes_key[32]);

/*
 * ota_verify_feed -- feed the next chunk of the OTA image stream.
 *
 * Data must be fed in order, starting from byte 0 of the signed image.
 * Internally the function:
 *   - Accumulates the 44-byte header on first call(s).
 *   - After the header is complete, begins streaming ciphertext into the
 *     OTA flash partition (via esp_ota_write) while hashing (header+ct).
 *   - On the last chunk (which contains the 64-byte trailing signature),
 *     separates the signature from the ciphertext stream.
 *
 * total_image_len: total length of the OTA image including the 64-byte sig.
 *                  Must be provided once (on first call) and not changed.
 *
 * Returns OTA_VERIFY_OK on success, negative error code on failure.
 * After any failure the context must be freed with ota_verify_abort().
 */
ota_verify_err_t ota_verify_feed(ota_verify_ctx_t *ctx,
                                  const uint8_t    *data,
                                  size_t            len,
                                  size_t            total_image_len);

/*
 * ota_verify_end -- finalise the session.
 *
 * Verifies the ECDSA signature and AES-GCM tag.
 * On success:
 *   - Calls esp_ota_end() to finalise the flash write.
 *   - Calls esp_ota_set_boot_partition() to select the new partition.
 *   - Frees the context.
 *   - Returns OTA_VERIFY_OK.
 *
 * On any failure:
 *   - Does NOT call esp_ota_set_boot_partition().
 *   - Calls esp_ota_abort() to discard the partial write.
 *   - Frees the context.
 *   - Returns the relevant error code.
 *
 * The caller should esp_restart() after a successful return.
 */
ota_verify_err_t ota_verify_end(ota_verify_ctx_t *ctx);

/*
 * ota_verify_abort -- tear down the session without committing anything.
 *
 * Safe to call after any ota_verify_feed failure or if the SSH session
 * is interrupted mid-stream.  Frees the context.
 */
void ota_verify_abort(ota_verify_ctx_t *ctx);

/*
 * ota_verify_strerror -- human-readable string for an error code.
 */
const char *ota_verify_strerror(ota_verify_err_t err);

#ifdef __cplusplus
}
#endif
