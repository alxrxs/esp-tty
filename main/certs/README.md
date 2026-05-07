# EAP-TLS Certificates

Place real certificates here before building with `WIFI_USE_ENTERPRISE`. The three files required are:

| File | Content |
|---|---|
| `ca.pem` | CA certificate that signed the RADIUS server's TLS certificate |
| `client.crt` | Client certificate issued by the same CA, identifying this device |
| `client.key` | Unencrypted client private key (PKCS#8 PEM) |

Copy the `.example` files as a starting point, then replace the placeholder blocks with real PEM data. All three files are gitignored.

## Generating a self-signed test CA and client cert

```sh
# 1. Create a CA (valid 10 years, 2048-bit RSA or ed25519)
openssl req -newkey ed25519 -x509 -days 3650 -nodes \
    -keyout ca.key -out ca.pem \
    -subj "/CN=Lab CA/O=MyOrg"

# 2. Generate client key and CSR
openssl req -newkey ed25519 -nodes \
    -keyout client.key.trad -out client.csr \
    -subj "/CN=nanoconsole/O=MyOrg"

# 3. Convert key to PKCS#8 (required by ESP-IDF EAP client)
openssl pkcs8 -topk8 -nocrypt -in client.key.trad -out client.key

# 4. Sign the CSR with the CA
openssl x509 -req -days 365 -in client.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out client.crt
```

Install `ca.pem` on your RADIUS server as a trusted CA, and configure the server to accept the CN `nanoconsole` as a valid user identity.

## First-time build note

On the very first build with cert files present, PlatformIO/ninja may complain that `ca.pem.S` is not found before it has been generated. If this happens, run `pio run -e esp32s3` a second time — the .S generation and the compilation are scheduled in the correct dependency order on the second invocation. This is a PlatformIO/ninja scheduling quirk with `EMBED_TXTFILES` in ESP-IDF 6.0.

## Note on time validation

The ESP32 EAP supplicant checks certificate expiry against the system clock. If the device has no SNTP sync at boot and you see authentication failures, set `#define EAP_DISABLE_TIME_CHECK 1` in `config.h` temporarily. Remove it once you have SNTP configured.
