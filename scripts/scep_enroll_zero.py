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

# Enrollment parameters: pulled from environment, with safe stubs for tests.
# The previous "real" defaults baked into source (a single-use NDES OTP and
# a fixed MAC) are removed since the script is committed to git; export the
# values at run time instead, e.g.:
#   export SCEP_URL='https://scep.example.com/certsrv/mscep/mscep.dll'
#   export SCEP_CHALLENGE_PASSWORD='...'
#   export SCEP_DEVICE_MAC='ac276ecec4e0'
#   ./scripts/scep_enroll_zero.py

# Sentinel: defer env-var lookup to call time so callers can set env vars
# after import and see the updated values.
_ENV_DEFAULT = object()


def do_enroll(scep_url=_ENV_DEFAULT,
              password=_ENV_DEFAULT,
              cn=None,
              output_dir=_ENV_DEFAULT,
              zero_mac=_ENV_DEFAULT):
    """
    Perform SCEP enrollment against *scep_url* and write the three PEM
    files (ca.pem, client.crt, client.key) into *output_dir*.

    Parameters
    ----------
    scep_url : str
        Full URL of the SCEP endpoint (e.g. https://…/mscep.dll).
    password : str
        SCEP challenge password (OTP from NDES / CA admin).
    cn : str or None
        CommonName for the certificate subject.  Defaults to
        ``IRIX-TTY-PVE-DELL-<zero_mac>``.
    output_dir : str
        Directory to write ca.pem, client.crt, client.key into.
        The directory must exist.
    zero_mac : str
        MAC address suffix used to build the default CN when *cn* is None.
    """
    # Defer env-var lookup to call time (so callers can set env vars after import).
    # Strip whitespace to avoid silent HTTP failures from trailing spaces/newlines.
    if scep_url is _ENV_DEFAULT:
        scep_url = os.environ.get("SCEP_URL",
                                  "https://scep.example.com/certsrv/mscep/mscep.dll").strip()
    else:
        scep_url = scep_url.strip()

    if password is _ENV_DEFAULT:
        password = os.environ.get("SCEP_CHALLENGE_PASSWORD", "").strip()
    else:
        password = password.strip()

    if output_dir is _ENV_DEFAULT:
        output_dir = os.environ.get("SCEP_OUTPUT_DIR",
                                    "/root/esp-tty/main/certs").strip()
    else:
        output_dir = output_dir.strip()

    if zero_mac is _ENV_DEFAULT:
        zero_mac = os.environ.get("SCEP_DEVICE_MAC", "000000000000").strip()
    else:
        zero_mac = zero_mac.strip()

    # Fail fast if the challenge password is empty -- sending an empty OTP to
    # NDES would result in a silent rejection rather than a clear error.
    if not password:
        raise ValueError(
            "SCEP challenge password is empty.  "
            "Set the SCEP_CHALLENGE_PASSWORD environment variable before running."
        )

    if cn is None:
        cn = f"IRIX-TTY-PVE-DELL-{zero_mac}"

    print(f">>> SCEP enrolment for CN={cn}")
    print(f"    URL: {scep_url}")

    # 1. Use PyScep helper: generate RSA-2048 key + CSR with challengePassword
    print(">>> generating key + CSR ...")
    csr, private_key = SigningRequest.generate_csr(
        cn=cn,
        key_usage={u"digital_signature", u"key_encipherment"},
        password=password,
    )

    # 2. Self-signed transient identity cert used as the PKCS#7 signer
    print(">>> building self-signed identity ...")
    identity_cert, _ = SigningRequest.generate_self_signed(
        cn=cn,
        key_usage={u"digital_signature", u"key_encipherment"},
        private_key=private_key,
    )

    # 3. NDES round-trip
    print(">>> calling NDES ...")
    client = Client(scep_url)
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

    os.makedirs(output_dir, exist_ok=True)
    ca_path     = os.path.join(output_dir, "ca.pem")
    crt_path    = os.path.join(output_dir, "client.crt")
    key_path    = os.path.join(output_dir, "client.key")
    with open(ca_path,  "wb") as f: f.write(ca_pem)
    with open(crt_path, "wb") as f: f.write(client_pem)
    with open(key_path, "wb") as f: f.write(key_pem)
    # client.key is a private key -- restrict to owner read/write only.
    os.chmod(key_path, 0o600)

    print(f">>> wrote {output_dir}/{{ca.pem,client.crt,client.key}}")
    print(f"    ca.pem     = {len(ca_pem)} B")
    print(f"    client.crt = {len(client_pem)} B")
    print(f"    client.key = {len(key_pem)} B")

    return {
        "ca_pem":     ca_pem,
        "client_pem": client_pem,
        "key_pem":    key_pem,
        "issued":     issued,
        "ca_list":    ca_list,
        "private_key": private_key,
    }


if __name__ == "__main__":
    do_enroll()
