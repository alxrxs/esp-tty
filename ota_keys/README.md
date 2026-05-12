# ota_keys/ — OTA firmware signing and encryption keys

This directory holds the cryptographic key material used to sign and encrypt
OTA firmware images for esp-tty. Three files make up a complete key set:
`sign.key.pem` (ECDSA-P256 private key), `sign.pub.pem` (the matching public
key), and `aes.key` (a 32-byte AES-256-GCM encryption key). All three are
gitignored. Two placeholder files — `sign.pub.pem.example` and
`aes.key.example` — are tracked in version control to document the expected
format and file names without exposing real secrets.

## How the keys are used

`sign.pub.pem` and `aes.key` are embedded directly into the firmware binary at
compile time via ESP-IDF's `EMBED_TXTFILES` / `EMBED_FILES` mechanism (see
`main/CMakeLists.txt`, the "OTA signing key embedding" section). This produces
the linker symbols `_binary_sign_pub_pem_start/_end` and
`_binary_aes_key_start/_end`, which the on-device OTA verifier uses to
authenticate and decrypt incoming images. If either file is absent when CMake
configures the build, the firmware is built without embedded key material and
the OTA session will fail gracefully at runtime; the missing-key path is
guarded by the `OTA_KEYS_EMBEDDED` compile-time definition.

When you want to ship a firmware update, run `scripts/sign_firmware.py` on the
build host. The script reads `sign.key.pem` (private key) and `aes.key`, then
produces a self-contained `.ota` image with the format: an 8-byte magic header
(`ESPOTA1\0`), a 4-byte version word, a 4-byte plaintext-length field, a
12-byte random AES-IV, a 16-byte GCM authentication tag, the AES-256-GCM
ciphertext, and finally a 64-byte ECDSA-P256 raw `r||s` signature that covers
every byte from the magic header through the end of the ciphertext. After
writing the image the script runs a self-test that parses and re-verifies it
before returning.

## Generating keys

Run the generator once per device fleet. The script is idempotent in the safe
direction: it will refuse to overwrite existing key files.

```sh
scripts/gen_ota_key.sh
```

This calls `openssl ecparam` to create `sign.key.pem` (mode 600), derives
`sign.pub.pem` from it (mode 644), and writes 32 random bytes from
`openssl rand` to `aes.key` (mode 600). It then performs sanity checks
(exact byte count on the AES key, P-256 curve confirmation on the public key)
before reporting success. The target directory can be overridden with the
`OTA_KEYS_DIR` environment variable, which the test suite uses to generate keys
in an isolated temporary location.

## File reference

| File | Purpose | Tracked? |
|------|---------|---------|
| `sign.key.pem` | ECDSA-P256 private key — used by `scripts/sign_firmware.py` | Gitignored |
| `sign.pub.pem` | ECDSA-P256 public key — embedded in firmware via `EMBED_TXTFILES` | Gitignored |
| `aes.key` | 32 raw bytes AES-256-GCM key — embedded in firmware via `EMBED_FILES` | Gitignored |
| `sign.pub.pem.example` | Placeholder showing expected PEM format | Tracked |
| `aes.key.example` | Placeholder (32 zero bytes) showing expected binary format | Tracked |
| `README.md` | This file | Tracked |

The `.gitignore` at the repository root explicitly ignores
`ota_keys/sign.key.pem`, `ota_keys/sign.pub.pem`, and `ota_keys/aes.key`,
and uses `!ota_keys/*.example` and `!ota_keys/README.md` exception rules to
keep the placeholders and documentation tracked.

## Security notes

`sign.key.pem` and `aes.key` must never be committed to version control. Back
them up in a secure secret store (for example, age-encrypted storage, a
hardware security module, or a secrets manager) immediately after generation.
Losing `sign.key.pem` means you cannot deliver authenticated OTA updates to
any device running the current firmware; losing `aes.key` means you cannot
encrypt future images for those devices. A device that receives an image with
an invalid signature or a failing GCM authentication tag will refuse to apply
the update and continue running the previous firmware, so key rotation or loss
does not brick fielded hardware. Rebuilding the firmware with a new keypair and
flashing it over USB is always available as a recovery path.
