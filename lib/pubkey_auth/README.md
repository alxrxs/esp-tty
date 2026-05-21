# lib/pubkey_auth -- OpenSSH public key parsing and SSH auth

This module handles every step of public key authentication for the wolfSSH
server, from reading an OpenSSH `authorized_keys` line at boot to comparing
a presented key inside the wolfSSH user-auth callback. It was extracted from
`main/ssh_server.c` so the logic can be unit-tested natively, without wolfSSH,
a live TCP connection, or a FreeRTOS task.

## Files

- **pubkey_auth.h** -- public interface. Declares `pubkey_parse_b64`,
  `pubkey_compute_hash`, `pubkey_auth_check`, `pubkey_classify_user`, and
  `format_fingerprint`, along with the `PUBKEY_HASH_SIZE` constant (32) and
  the `pubkey_auth_result_t` and `pubkey_user_class_t` enumerations.
- **pubkey_auth.c** -- implementation. Uses wolfCrypt's `Sha256` and
  `Base64_Decode` on-device; the native test build supplies OpenSSL 3 EVP
  stubs from `test/stubs/wolfssl/wolfcrypt/sha256.h`.

## Parsing and hash framing

`pubkey_parse_b64` locates the base64 field in an OpenSSH public key line of
the form `"ssh-ed25519 AAAA... comment"`. It skips the key-type token (up to
the first space), records the start and byte-length of the base64 field (up to
the next space, CR, LF, or NUL), and returns false for any malformed input.
`pubkey_compute_hash` calls `pubkey_parse_b64`, base64-decodes the blob into a
512-byte stack buffer (blobs larger than 512 bytes are rejected), then computes
`SHA-256( uint32be(blob_len) || blob )` -- a four-byte big-endian length prefix
followed by the raw wire blob. This framing ensures that two keys whose blobs
are byte-for-byte identical except for length produce different digests. The
resulting 32-byte hash is the canonical identity stored in `s_authkey_hashes[]`
at startup and compared against every connecting client. Trailing comment fields
are ignored because `pubkey_parse_b64` stops at the first space after the
base64 token; the hash is therefore the same whether or not a comment is
present.

## Constant-time comparison in `pubkey_auth_check`

When wolfSSH calls `user_auth_callback` it passes the raw wire blob of the
presented key. `pubkey_auth_check` applies the same `SHA-256( uint32be(sz) ||
blob )` framing to the presented blob and then compares all 32 bytes of the
resulting digest against the stored `expected_hash` using a `volatile uint8_t`
XOR accumulator:

```c
volatile uint8_t diff = 0;
for (size_t i = 0; i < PUBKEY_HASH_SIZE; i++)
    diff |= digest[i] ^ expected_hash[i];
return (diff == 0) ? PUBKEY_AUTH_OK : PUBKEY_AUTH_REJECTED;
```

The `volatile` qualifier prevents the compiler from short-circuiting the loop
on the first differing byte, which `memcmp` is permitted to do. The function
returns `PUBKEY_AUTH_REJECTED` immediately for a NULL or zero-length key,
before any hashing occurs.

## Username routing via `pubkey_classify_user`

`pubkey_classify_user` maps the SSH username received during handshake to one
of three values: `PUBKEY_USER_TTY` for the exact string `"tty"`,
`PUBKEY_USER_OTA` for the exact string `"ota"`, and `PUBKEY_USER_REJECTED` for
everything else -- including NULL, empty strings, case variants such as `"TTY"`,
and any string with leading or trailing whitespace. The comparison is
case-sensitive and length-exact; the length is the SSH wire field length, not a
NUL-terminated strlen, so embedded NUL bytes or claimed lengths that differ from
the printable content are rejected cleanly. In `user_auth_callback`,
`PUBKEY_USER_REJECTED` causes an immediate `WOLFSSH_USERAUTH_FAILURE` before any
key material is examined; `PUBKEY_USER_OTA` routes to the single
`s_ota_authkey_hash`; and `PUBKEY_USER_TTY` iterates over `s_authkey_hashes[]`
accepting if any slot matches. After a successful handshake, `ssh_server.c`
calls `pubkey_classify_user` a second time on the negotiated username to decide
whether to start the USB-CDC bridge (`tty`) or hand off to `ota_session_handler`
(`ota`).

## Boot-log display with `format_fingerprint`

`format_fingerprint` formats a 32-byte SHA-256 digest as colon-separated
lowercase hex (e.g. `"8b:2e:eb:84:..."`) into a caller-supplied buffer of at
least 96 bytes (`PUBKEY_HASH_SIZE * 3`). It is used at startup to log each
loaded key's fingerprint via `ESP_LOGI` so operators can confirm which keys are
active without storing the raw public key material in flash or logs.

## Native testability

The module has no direct dependency on ESP-IDF or FreeRTOS outside the
`ESP_LOG*` calls, which are stubbed for native builds. Three Unity test
suites exercise it on the host:

- `test/native/test_pubkey_auth/` -- covers `pubkey_parse_b64` and
  `pubkey_compute_hash`, including a golden-value SHA-256 check,
  comment-field independence, and boundary conditions for the 512-byte
  internal blob buffer.
- `test/native/test_auth_check/` -- covers `pubkey_auth_check`: accept,
  single-byte-difference rejection, length-prefix rejection, multi-key
  iteration semantics, and a behavioural witness that the XOR accumulator
  inspects all 32 bytes rather than stopping early.
- `test/native/test_user_class/` -- covers `pubkey_classify_user`: exact
  matches, case variants, whitespace padding, embedded NUL bytes, Unicode
  byte sequences, and very long inputs.
