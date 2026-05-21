# lib/scep_proto -- SCEP wire-protocol primitives

SCEP (RFC 8894) certificate enrolment library for esp-tty. Pure C, no ESP-IDF
or FreeRTOS dependencies, no network I/O -- everything is in-memory build /
parse of DER bytes. All crypto goes through mbedTLS (`mbedtls_pk`,
`mbedtls_rsa`, `mbedtls_x509write_*`, `mbedtls_aes`, `mbedtls_asn1*`,
`mbedtls_sha256`). The same source compiles on-device (ESP-IDF ships mbedTLS)
and against system mbedTLS for native unit tests.

Target CA: Microsoft NDES (`/certsrv/mscep/mscep.dll`) in legacy CryptoAPI /
CSP mode, end-to-end tested. Key algorithm is RSA-2048 with SHA-256 (PKCS#1
v1.5); NDES legacy mode rejects ECDSA-signed pkiMessages with
`failInfo=badMessageCheck`.

## Public API

See `scep_proto.h` for full doc comments with RFC section references.

| Function | Purpose |
|---|---|
| `scep_generate_keypair` | Generate an RSA-2048 key pair into a `mbedtls_pk_context` |
| `scep_build_csr` | Build a PKCS#10 CSR with the SCEP `challengePassword` attribute |
| `scep_build_self_signed_cert` | Build the transient signer cert used in the pkiMessage SignerInfo |
| `scep_transaction_id` | Derive `hex(SHA-256(SPKI))` per RFC 8894 §3.1 |
| `scep_build_pkimessage_pkcsreq` | Build a PKCSReq pkiMessage: `SignedData(EnvelopedData(CSR))` |
| `scep_parse_certrep` | Parse a CertRep response, decrypt the EnvelopedData, extract the issued cert DER, return pkiStatus / failInfo |
| `scep_parse_getcacert` | Parse the degenerate-PKCS#7 GetCACert response into a CA + RA-sign + RA-encrypt bundle (pointers alias the input buffer) |
| `scep_parse_pkimessage_pkcsreq_for_test` | Reverse of `scep_build_pkimessage_pkcsreq`.  Declared in the separate `scep_proto_test_helpers.h`, included only by tests built with `-DSCEP_PROTO_TEST_HELPERS` |

EnvelopedData content encryption is AES-256-CBC; signatures and signed
attributes follow CMS / PKCS#7. The library does no transport: callers
combine it with `lib/scep_transport/` (HTTPS via `esp_http_client`) and
`lib/cred_store/` (NVS persistence) -- `main/scep_enroll.c` is the
orchestrator.

## Callers

- `main/scep_enroll.c` -- one-shot enrolment on first boot.
- `main/cert_renewer.c` -- background task that re-enrols before the stored
  cert's `NotAfter` falls inside `CERT_RENEWAL_WINDOW_DAYS`.

## Tests

- `test/native/test_scep_proto/` -- builds + reparses CSRs and pkiMessages,
  exercises the transaction-ID derivation, error / NULL guards, and the
  single- vs multi-cert GetCACert bundle paths against an in-process
  mbedTLS CA.
- `test/scripts/test_scep_protocol_e2e.py` -- end-to-end roundtrip against
  the in-process `FakeNdesCA` Python fixture (success, failure, pending,
  malformed CertRep, single- and multi-cert bundle responses).
- `test/embedded/test_scep_proto_smoke/` -- on-device smoke (gated on a
  build flag; not run in normal CI).
