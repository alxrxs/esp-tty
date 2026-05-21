# main/certs -- Embedded PEM Trust Material

This directory holds the PEM files that `main/CMakeLists.txt` embeds into the
firmware binary via the `EMBED_TXTFILES` mechanism. Two independent groups
live here:

| Group | Files | Required for | Linker symbols |
|---|---|---|---|
| EAP-TLS bootstrap credentials | `ca.pem`, `client.crt`, `client.key` | `WIFI_USE_ENTERPRISE` builds (Mode B -- static EAP-TLS) | `_binary_ca_pem_start/_end`, `_binary_client_crt_start/_end`, `_binary_client_key_start/_end` |
| SCEP server TLS trust anchor | `scep_ca.pem` | SCEP enrolment (Mode C -- on-device auto-enrolment) | `_binary_scep_ca_pem_start/_end` |

For every real file there is a tracked `.pem.example` / `.crt.example` /
`.key.example` placeholder. The real files (`ca.pem`, `client.crt`,
`client.key`, `scep_ca.pem`) are gitignored via the
`main/certs/*.pem` / `*.crt` / `*.key` rules in the root `.gitignore`, with
`!main/certs/*.example` preserving the placeholders. Never commit real key
material.

## EAP-TLS files

| File | Content |
|---|---|
| `ca.pem` | CA certificate that signed the RADIUS server's TLS certificate |
| `client.crt` | Client certificate issued by the same CA, identifying this device |
| `client.key` | Unencrypted client private key (PKCS#8 PEM) |

These are read by `main/wifi.c` and handed to ESP-IDF's EAP supplicant when
the firmware switches the STA into WPA2/WPA3-Enterprise mode. They are only
needed when `WIFI_USE_ENTERPRISE` is defined in `config.h`; otherwise the
directory is ignored and the firmware uses WPA2/WPA3-Personal.

### Generating a self-signed lab CA + client cert

```sh
# 1. Create a CA (valid 10 years)
openssl req -newkey ed25519 -x509 -days 3650 -nodes \
    -keyout ca.key -out ca.pem \
    -subj "/CN=Lab CA/O=MyOrg"

# 2. Generate client key and CSR
openssl req -newkey ed25519 -nodes \
    -keyout client.key.trad -out client.csr \
    -subj "/CN=nanoconsole/O=MyOrg"

# 3. Convert key to PKCS#8 (required by the ESP-IDF EAP supplicant)
openssl pkcs8 -topk8 -nocrypt -in client.key.trad -out client.key

# 4. Sign the CSR with the CA
openssl x509 -req -days 365 -in client.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out client.crt
```

Install `ca.pem` on the RADIUS server as a trusted CA and configure it to
accept the CN `nanoconsole` as a valid EAP identity. Substitute `rsa:2048`
for `ed25519` if your RADIUS server does not support EdDSA.

## SCEP file

`scep_ca.pem` is the TLS trust anchor for HTTPS connections to the SCEP
server (`SCEP_URL`). It must contain the full chain from the SCEP server's
TLS leaf certificate up to and including the root CA, in PEM format. It is
consumed by `lib/scep_transport/` via `esp_http_client` and is independent
of the CA that signs the issued device certificate.

Copy `scep_ca.pem.example` to `scep_ca.pem` and paste in the real chain
before building. If the file is absent, `main/CMakeLists.txt` skips the
embed and prints `SCEP transport disabled`; the SCEP enrolment path then
cannot run.

## How the files reach the firmware

`main/CMakeLists.txt` checks at CMake configure time whether the real files
are present and passes the ones that exist to `EMBED_TXTFILES` in
`idf_component_register`. ESP-IDF assembles each file into a read-only data
section and exposes the linker symbols listed in the table above. The cert
paths are registered as `CMAKE_CONFIGURE_DEPENDS` entries, so adding or
removing a file automatically triggers a CMake reconfigure on the next
`pio run`.

## Certificate time validation (EAP-TLS)

The ESP32 EAP supplicant validates certificate expiry against the system
clock. If the device has not completed an SNTP sync at boot and
authentication fails with a time-related error, set
`#define EAP_DISABLE_TIME_CHECK 1` in `config.h` temporarily. Remove it once
SNTP is configured and the RTC is kept accurate.
