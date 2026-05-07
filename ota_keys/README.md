# ota_keys/ — OTA firmware signing keys

This directory holds the ECDSA-P256 signing keypair and AES-256 encryption key
used to sign and encrypt OTA firmware images for esp-tty.

## Files

| File | Purpose | Tracked? |
|------|---------|---------|
| `sign.key.pem` | ECDSA-P256 private key — sign firmware with `scripts/sign_firmware.py` | **Gitignored** |
| `sign.pub.pem` | ECDSA-P256 public key — embedded into firmware at compile time via `EMBED_TXTFILES` | **Gitignored** |
| `aes.key` | 32 raw bytes AES-256-GCM encryption key — embedded into firmware via `EMBED_FILES` | **Gitignored** |
| `sign.pub.pem.example` | Placeholder showing expected PEM format | Tracked |
| `aes.key.example` | Placeholder (32 zero bytes) showing expected format | Tracked |
| `README.md` | This file | Tracked |

## Generating keys

Run once per device fleet (never overwrite existing keys without understanding the consequences):

```sh
scripts/gen_ota_key.sh
```

This creates `sign.key.pem`, `sign.pub.pem`, and `aes.key` in this directory.

## Signing firmware

```sh
python3 scripts/sign_firmware.py .pio/build/esp32s3/firmware.bin
# Produces: .pio/build/esp32s3/firmware.bin.ota
```

## Uploading OTA

```sh
ssh -i ~/.ssh/id_ed25519 -p 2222 ota@<device-ip> < .pio/build/esp32s3/firmware.bin.ota
```

## Security notes

- `sign.key.pem` and `aes.key` must **never** be committed to version control.
- Back them up in a secure secret store (e.g., age-encrypted, hardware key, secrets manager).
- If `sign.key.pem` is lost, you cannot deliver signed OTA updates to fielded devices.
- If `aes.key` is lost, you cannot encrypt future OTA images (but existing firmware is unaffected).
- A device that receives a firmware image with invalid signature or tag will refuse to boot it
  and continue running the previous firmware (rollback-safe by design).
