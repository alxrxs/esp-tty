# lib/scep_proto -- SCEP wire-protocol primitives

SCEP (RFC 8894) certificate enrolment library for esp-tty.

Target CA: Microsoft NDES (`/certsrv/mscep/mscep.dll`).

No ESP-IDF dependencies, no network I/O. All crypto via wolfSSL.

## API

See `scep_proto.h` for full doc comments with RFC section references.

| Function | Purpose |
|---|---|
| `scep_generate_keypair` | Generate ECDSA P-256 key |
| `scep_build_csr` | Build PKCS#10 CSR with challengePassword |
| `scep_build_self_signed_cert` | Build transient signer cert |
| `scep_transaction_id` | Derive hex(SHA-256(SPKI)) transaction ID |
| `scep_build_pkimessage_pkcsreq` | Build PKCSReq pkiMessage |
| `scep_parse_certrep` | Parse CertRep, decrypt issued cert |
| `scep_parse_getcacert` | Parse GetCACert degenerate P7 |
| `scep_parse_pkimessage_pkcsreq_for_test` | Test-only reverse path (`-DSCEP_PROTO_TEST_HELPERS`) |

## wolfSSL user_settings.h additions required

```c
/* SCEP wire-protocol support */
#define HAVE_PKCS7          /* wc_PKCS7_* API (SignedData + EnvelopedData) */
#define WOLFSSL_CERT_GEN    /* wc_MakeCert, wc_InitCert, wc_MakeSelfCert  */
#define WOLFSSL_CERT_REQ    /* wc_MakeCertReq + Cert.challengePw field     */
#define HAVE_AES_CBC        /* AES-256-CBC for EnvelopedData content enc   */
```

`HAVE_ECC`, `WOLFSSL_SHA256` are already present from the SSH host-key config.
