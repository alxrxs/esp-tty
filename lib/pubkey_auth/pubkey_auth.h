/*
 * pubkey_auth.h — OpenSSH public key parsing and hash-based auth
 *
 * Extracted from ssh_server.c so the logic can be unit-tested natively
 * without wolfSSH or a live TCP connection.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define PUBKEY_HASH_SIZE  32   /* SHA-256 */

/*
 * Parse an OpenSSH public key line ("ssh-ed25519 AAAA... comment") and
 * locate the base64 blob within it.
 *
 * On success, sets *b64_start to the first character of the base64 field
 * and *b64_len to its length (bytes up to next space/NUL).
 * Returns true on success, false if the string is malformed.
 */
bool pubkey_parse_b64(const char *openssh_line,
                      const char **b64_start, size_t *b64_len);

/*
 * Decode the base64 blob from an OpenSSH public key line and compute
 * SHA-256( uint32be(blob_len) || blob ), writing 32 bytes to hash_out.
 * Returns true on success.
 *
 * This hash is used both at startup (authorized key registration) and
 * in the wolfSSH auth callback (comparing against the presented key).
 */
bool pubkey_compute_hash(const char *openssh_line,
                         uint8_t hash_out[PUBKEY_HASH_SIZE]);

/* ------------------------------------------------------------------ */
/* Auth check helper — extracted so it can be unit-tested natively    */
/* ------------------------------------------------------------------ */

/*
 * pubkey_auth_result_t — return type for pubkey_auth_check().
 */
typedef enum {
    PUBKEY_AUTH_OK,       /* presented key matches expected_hash */
    PUBKEY_AUTH_REJECTED, /* presented key does not match, or is invalid */
} pubkey_auth_result_t;

/*
 * Compute SHA-256( uint32be(presented_key_sz) || presented_key ), compare
 * against expected_hash using a constant-time comparison, and return
 * PUBKEY_AUTH_OK or PUBKEY_AUTH_REJECTED.
 *
 * Returns PUBKEY_AUTH_REJECTED for NULL presented_key or presented_key_sz == 0.
 */
pubkey_auth_result_t pubkey_auth_check(
    const uint8_t *presented_key, size_t presented_key_sz,
    const uint8_t  expected_hash[PUBKEY_HASH_SIZE]);

/* ------------------------------------------------------------------ */
/* Username classification — routes auth to the correct key hash     */
/* ------------------------------------------------------------------ */

/*
 * pubkey_user_class_t — result of classifying an SSH username.
 */
typedef enum {
    PUBKEY_USER_DEFAULT,  /* normal session: use the default authkey hash */
    PUBKEY_USER_OTA,      /* OTA session: use the OTA authkey hash        */
    PUBKEY_USER_REJECTED, /* reserved for future use (e.g. anonymous)     */
} pubkey_user_class_t;

/*
 * pubkey_classify_user — classify an SSH username string.
 *
 * username     : pointer to the username bytes (may be NULL)
 * username_sz  : byte length of the username (NOT including NUL)
 *
 * Returns PUBKEY_USER_OTA if the username is exactly "ota" (length 3,
 * case-sensitive).  Returns PUBKEY_USER_DEFAULT in all other cases.
 * NULL-safe (returns PUBKEY_USER_DEFAULT for NULL username).
 */
pubkey_user_class_t pubkey_classify_user(const char *username, size_t username_sz);

/* ------------------------------------------------------------------ */
/*
 * Format a 32-byte SHA-256 digest as colon-separated lowercase hex,
 * e.g. "8b:2e:eb:84:...".  out must be at least PUBKEY_HASH_SIZE*3 bytes
 * (96 bytes is enough for 32 bytes with colons and NUL terminator).
 * Returns out on success, NULL if out_sz is too small.
 */
char *format_fingerprint(const uint8_t digest[PUBKEY_HASH_SIZE],
                         char *out, size_t out_sz);
