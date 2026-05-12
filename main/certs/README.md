# EAP-TLS Certificates

This directory holds the three PEM files that authenticate the device to a
WPA2-Enterprise (EAP-TLS) network. They are only required when
`WIFI_USE_ENTERPRISE` is defined in `config.h`. Without that define the
directory is ignored entirely and the firmware uses ordinary WPA2-PSK.

| File | Content |
|---|---|
| `ca.pem` | CA certificate that signed the RADIUS server's TLS certificate |
| `client.crt` | Client certificate issued by the same CA, identifying this device |
| `client.key` | Unencrypted client private key (PKCS#8 PEM) |

Three `.example` placeholder files (`ca.pem.example`, `client.crt.example`,
`client.key.example`) are tracked in git and show the expected PEM structure.
The real files -- `ca.pem`, `client.crt`, and `client.key` -- are gitignored via
the `main/certs/*.pem`, `main/certs/*.crt`, and `main/certs/*.key` rules in
`.gitignore`, with `!main/certs/*.example` preserving the stubs. Never commit
real key material.

## Generating a self-signed test CA and client cert

The commands below produce a minimal EAP-TLS credential set suitable for a lab
RADIUS server. Use ed25519 keys for small PEM size; substitute `rsa:2048` if
your RADIUS server does not support EdDSA.

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
accept the CN `nanoconsole` as a valid EAP identity. For production use,
generate the client certificate from your existing PKI instead of this
self-signed CA.

## How the files reach the firmware

`main/CMakeLists.txt` checks at CMake configure time whether all three real
cert files are present. When they are, it passes them to the
`EMBED_TXTFILES` directive of `idf_component_register`, which causes the
ESP-IDF build system to assemble each file into a read-only data section and
expose linker symbols of the form `_binary_<name>_start` /
`_binary_<name>_end`. The symbols consumed in `wifi.c` are:

```
_binary_ca_pem_start    / _binary_ca_pem_end
_binary_client_crt_start / _binary_client_crt_end
_binary_client_key_start / _binary_client_key_end
```

CMake registers the cert paths as `CMAKE_CONFIGURE_DEPENDS` entries, so
adding or removing the files automatically triggers a CMake reconfigure on
the next `pio run` -- a single build invocation is always sufficient.

## Certificate time validation

The ESP32 EAP supplicant validates certificate expiry against the system
clock. If the device has not yet completed an SNTP sync at boot and
authentication fails with a time-related error, set
`#define EAP_DISABLE_TIME_CHECK 1` in `config.h` temporarily. Remove it once
SNTP is configured and the RTC is kept accurate.
