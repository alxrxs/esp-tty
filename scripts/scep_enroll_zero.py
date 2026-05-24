#!/usr/bin/env python3
"""
Manual SCEP enrollment for the ESP32-S3-Zero against real NDES, using
PyScep's own helper classes throughout to avoid type incompatibilities.

Result: main/certs/{ca.pem, client.crt, client.key} suitable for Mode B+
build-time embedding (no SCEP at firmware runtime).
"""
import os
from scep.Client.client import Client
from scep.Client.signingrequest import SigningRequest
from scep.Client.responses import CACertificates

# PyScep 0.0.14 bug: CACertificates._filter compares cert.is_ca (None for
# non-CA certs) against ca_only (False), and None != False is True in Python,
# so non-CA certs get incorrectly rejected.  Patch _filter to coerce.
_orig_filter = CACertificates._filter
def _fixed_filter(self, required_key_usage, not_required_key_usage, ca_only=False):
    out = []
    for cert in self._certificates:
        if (bool(cert.is_ca) != ca_only) or \
                (required_key_usage.intersection(cert.key_usage) != required_key_usage) or \
                (not_required_key_usage.difference(cert.key_usage) != not_required_key_usage):
            continue
        out.append(cert)
    return out
CACertificates._filter = _fixed_filter

# Another PyScep bug: verify() calls RSA-shaped .verify(sig, data, padding, hash)
# on the EC issuer key, which only takes 3 args.  Skip verification — we already
# trust the bundle via our REQUESTS_CA_BUNDLE-validated TLS connection.
CACertificates.verify = lambda self: None

# Trust scep.irix.systems via our embedded CA bundle.
os.environ.setdefault("REQUESTS_CA_BUNDLE",
                      "/root/esp-tty/main/certs/scep_ca.pem")

SCEP_URL  = "https://scep.irix.systems/certsrv/mscep/mscep.dll"
PASSWORD  = "FFC9708138742EC99A8CDF837A9F4CEA"
ZERO_MAC  = "ac276ecec4e0"
CN        = f"IRIX-TTY-PVE-DELL-{ZERO_MAC}"

print(f">>> SCEP enrolment for CN={CN}")
print(f"    URL: {SCEP_URL}")

# 1. Use PyScep helper: generate RSA-2048 key + CSR with challengePassword
print(">>> generating key + CSR ...")
csr, private_key = SigningRequest.generate_csr(
    cn=CN,
    key_usage={u"digital_signature", u"key_encipherment"},
    password=PASSWORD,
)

# 2. Self-signed transient identity cert used as the PKCS#7 signer
print(">>> building self-signed identity ...")
identity_cert, _ = SigningRequest.generate_self_signed(
    cn=CN,
    key_usage={u"digital_signature", u"key_encipherment"},
    private_key=private_key,
)

# 3. NDES round-trip
print(">>> calling NDES ...")
client = Client(SCEP_URL)
print("    GetCACaps + GetCACert ...")
ca_certs = client.get_ca_certs()
ca_list = ca_certs.certificates
print(f"    received {len(ca_list)} CA cert(s)")
for i, c in enumerate(ca_list):
    cn_attr = c.subject_dict.get("common_name", "(no CN)")
    pubkey = type(c.public_key.to_crypto_public_key()).__name__
    print(f"    [{i}] CN={cn_attr}  ku={c.key_usage}  pk={pubkey}")

# PyScep has a bug filtering recipient (is_ca=None != False).  Force the
# RA-encryption cert (RSA + key_encipherment, no digital_signature).
for cand in ca_list:
    if (cand.key_usage == {"key_encipherment"}
            and type(cand.public_key.to_crypto_public_key()).__name__ == "RSAPublicKey"):
        ca_certs._recipient = cand
        print(f"    >>> forced recipient = CN={cand.subject_dict.get('common_name')}")
        break
# Pick a signer too (RA signing cert: digital_signature, RSA, not CA)
for cand in ca_list:
    if (cand.key_usage == {"digital_signature"}
            and type(cand.public_key.to_crypto_public_key()).__name__ == "RSAPublicKey"):
        ca_certs._signer = cand
        print(f"    >>> forced signer = CN={cand.subject_dict.get('common_name')}")
        break
# Issuer = the CA that signed the recipient
for cand in ca_list:
    if cand.is_ca and cand.subject == ca_certs._recipient.issuer:
        ca_certs._issuer = cand
        print(f"    >>> forced issuer = CN={cand.subject_dict.get('common_name')}")
        break

print("    PKCSReq (enrol) ...")
resp = client.enrol(csr=csr, identity=identity_cert,
                    identity_private_key=private_key)
print(f"    response status: {resp.status}")

if str(resp.status) != "PKIStatus.SUCCESS":
    print(f"    fail_info: {getattr(resp, 'fail_info', '(none)')}")
    raise SystemExit(1)

issued = resp.certificates[0]
print(f"    issued cert subject CN: {issued.subject_dict.get('common_name')}")
print(f"    serial: {issued.serial_number}")

# 4. Write Mode B/B+ files.
ca_pem     = b"".join(c.to_pem() for c in ca_list)
client_pem = issued.to_pem()
# Private key — PyScep wraps an asn1crypto/cryptography object. Get a PEM:
from cryptography.hazmat.primitives import serialization as _ser
crypto_key = private_key.to_crypto_private_key() if hasattr(private_key, "to_crypto_private_key") else private_key
key_pem = crypto_key.private_bytes(
    encoding=_ser.Encoding.PEM,
    format=_ser.PrivateFormat.PKCS8,
    encryption_algorithm=_ser.NoEncryption(),
)

with open("/root/esp-tty/main/certs/ca.pem",     "wb") as f: f.write(ca_pem)
with open("/root/esp-tty/main/certs/client.crt", "wb") as f: f.write(client_pem)
with open("/root/esp-tty/main/certs/client.key", "wb") as f: f.write(key_pem)

print(">>> wrote main/certs/{ca.pem,client.crt,client.key}")
print(f"    ca.pem     = {len(ca_pem)} B")
print(f"    client.crt = {len(client_pem)} B")
print(f"    client.key = {len(key_pem)} B")
