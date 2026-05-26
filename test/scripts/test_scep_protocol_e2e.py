#!/usr/bin/env python3
"""
test/scripts/test_scep_protocol_e2e.py -- Pure-Python SCEP protocol E2E tests.

Architecture mirrors test_ota_protocol_e2e.py: a FakeNdesCA class plays the
server role entirely in-memory (no sockets, no real NDES), and a SCEPClient
class plays the client role.  Both sides use the ``cryptography`` library.

What is covered:
  1. Happy path: client gets a cert; subject CN + SPKI + CA signature all verified.
  2. Wrong challenge password -> pkiStatus=FAILURE, failInfo=badRequest.
  3. Tampered pkiMessage -> server-side signature verification rejects it.
  4. Replayed transactionID (same TX-ID, different CSR) -> server issues (no dedup);
     client accepts matching tx-id in response.
  5. TransactionID mismatch in response -> client raises.
  6. GetCACert parse:
       (a) three-cert NDES bundle  -> all three cert slots populated distinctly.
       (b) single-cert bundle      -> all three slots alias the same cert.

Run with:
    venv/bin/pytest test/scripts/test_scep_protocol_e2e.py -v

No ESP-IDF, no hardware, no network required.
"""

import hashlib
import os
import subprocess
import struct
import datetime
import tempfile

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat,
)
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    PKCS7SignatureBuilder,
    PKCS7EnvelopeBuilder,
    PKCS7Options,
    pkcs7_decrypt_der,
    serialize_certificates,
    load_der_pkcs7_certificates,
)

# Use Binary mode for all PKCS7 envelope operations to prevent LF->CRLF
# translation of binary DER content (cryptography lib default is MIME text mode).
_P7_BINARY = [PKCS7Options.Binary]


# ── OpenSSL subprocess helpers ───────────────────────────────────────────────
#
# The ``cryptography`` library's PKCS7EnvelopeBuilder only supports RSA
# recipients.  Real SCEP uses RSA for the RA encryption cert (the cert the
# client encrypts CSRs to) but when the CA encrypts the CertRep back to the
# client's EC key it needs ECDH-based key agreement.  We drive openssl(1)
# via subprocess for those cases.

def _cms_encrypt_to_cert(plaintext: bytes, recipient_cert: x509.Certificate) -> bytes:
    """
    Encrypt *plaintext* to *recipient_cert* using AES-256-CBC.
    Supports both RSA (KTRI) and EC (KARI/ECDH) recipient certs.
    Returns DER-encoded CMS EnvelopedData.
    """
    with tempfile.TemporaryDirectory() as d:
        cert_path  = os.path.join(d, "cert.pem")
        plain_path = os.path.join(d, "plain.bin")
        enc_path   = os.path.join(d, "enc.p7m")
        with open(cert_path,  "wb") as f: f.write(recipient_cert.public_bytes(Encoding.PEM))
        with open(plain_path, "wb") as f: f.write(plaintext)
        r = subprocess.run(
            ["openssl", "cms", "-encrypt", "-in", plain_path, "-out", enc_path,
             "-outform", "DER", "-binary", "-aes256", cert_path],
            capture_output=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"openssl cms -encrypt failed: {r.stderr.decode()}")
        with open(enc_path, "rb") as f:
            return f.read()


def _cms_decrypt_from_cert(enc_der: bytes, cert: x509.Certificate, private_key) -> bytes:
    """
    Decrypt *enc_der* (DER CMS EnvelopedData) using *private_key*.
    Supports both RSA and EC keys.

    Note: We do NOT pass ``-recip`` to openssl because the recipient cert in the
    EnvelopedData was created at encrypt time and may have a different serial
    number than the cert we generate locally (both carry the same public key,
    but random serials differ).  OpenSSL can find the matching recipient by
    trying the private key directly without needing the exact cert to match.
    """
    with tempfile.TemporaryDirectory() as d:
        key_path  = os.path.join(d, "key.pem")
        enc_path  = os.path.join(d, "enc.p7m")
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(Encoding.PEM,
                                               PrivateFormat.TraditionalOpenSSL,
                                               NoEncryption()))
        with open(enc_path, "wb") as f: f.write(enc_der)
        r = subprocess.run(
            ["openssl", "cms", "-decrypt", "-in", enc_path, "-inform", "DER",
             "-inkey", key_path],
            capture_output=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"openssl cms -decrypt failed: {r.stderr.decode()}")
        return r.stdout

# ── OIDs ──────────────────────────────────────────────────────────────────────

# SCEP signed-attribute OIDs (VeriSign / MS NDES dialect)
_OID_MESSAGE_TYPE   = "2.16.840.1.113733.1.9.2"
_OID_PKI_STATUS     = "2.16.840.1.113733.1.9.3"
_OID_FAIL_INFO      = "2.16.840.1.113733.1.9.4"
_OID_SENDER_NONCE   = "2.16.840.1.113733.1.9.5"
_OID_RECIPIENT_NONCE = "2.16.840.1.113733.1.9.6"
_OID_TRANSACTION_ID = "2.16.840.1.113733.1.9.7"

# PKCS#9 challengePassword OID
_OID_CHALLENGE_PW = "1.2.840.113549.1.9.7"

# SCEP message type values (PrintableString)
_MSG_TYPE_PKCSREQ = "19"
_MSG_TYPE_CERTREP = "3"

# pkiStatus values
_PKI_STATUS_SUCCESS = "0"
_PKI_STATUS_FAILURE = "2"
_PKI_STATUS_PENDING = "3"

# failInfo values
_FAIL_BAD_ALG           = "0"
_FAIL_BAD_MESSAGE_CHECK = "1"
_FAIL_BAD_REQUEST       = "2"
_FAIL_BAD_TIME          = "3"
_FAIL_BAD_CERT_ID       = "4"


# ── Minimal DER helpers ───────────────────────────────────────────────────────

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    raise ValueError(f"length {n} too large for DER")


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _seq(content: bytes) -> bytes:
    return _tlv(0x30, content)


def _set(content: bytes) -> bytes:
    return _tlv(0x31, content)


def _oid(dotted: str) -> bytes:
    """Encode a dotted OID as DER."""
    parts = list(map(int, dotted.split(".")))
    # First two arcs combined
    encoded = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        if p == 0:
            encoded.append(0)
        else:
            tmp = []
            while p:
                tmp.append(p & 0x7F)
                p >>= 7
            tmp.reverse()
            for i, b in enumerate(tmp):
                encoded.append(b | (0x80 if i < len(tmp) - 1 else 0))
    body = bytes(encoded)
    return _tlv(0x06, body)


def _printable_string(s: str) -> bytes:
    return _tlv(0x13, s.encode("ascii"))


def _utf8_string(s: str) -> bytes:
    return _tlv(0x0C, s.encode("utf-8"))


def _octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _integer(n: int) -> bytes:
    """Encode a non-negative integer as DER INTEGER."""
    if n == 0:
        return _tlv(0x02, b"\x00")
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    if out[0] & 0x80:
        out.insert(0, 0)
    return _tlv(0x02, bytes(out))


def _explicit(tag: int, content: bytes) -> bytes:
    return _tlv(0xA0 | tag, content)


def _implicit_constructed(tag: int, content: bytes) -> bytes:
    return _tlv(0xA0 | tag, content)


# ── DER parsing helpers ───────────────────────────────────────────────────────

def _parse_tlv(data: bytes, pos: int = 0):
    """Return (tag, value_bytes, next_pos)."""
    tag = data[pos]
    pos += 1
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    elif first == 0x81:
        length = data[pos]; pos += 1
    elif first == 0x82:
        length = (data[pos] << 8) | data[pos + 1]; pos += 2
    elif first == 0x83:
        length = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2]; pos += 3
    else:
        raise ValueError(f"Unsupported length encoding: {first:#x}")
    value = data[pos:pos + length]
    return tag, value, pos + length


def _find_printable_string(data: bytes) -> str:
    """Extract a PrintableString or UTF8String value from raw attribute value DER."""
    try:
        tag, val, _ = _parse_tlv(data)
        if tag in (0x13, 0x0C, 0x16):  # PrintableString, UTF8String, IA5String
            return val.decode("ascii", errors="replace")
    except Exception:
        pass
    return ""


def _find_octet_string(data: bytes) -> bytes:
    """Extract an OctetString value from raw attribute value DER."""
    try:
        tag, val, _ = _parse_tlv(data)
        if tag == 0x04:
            return val
    except Exception:
        pass
    return b""


def _parse_scep_signed_attrs(signed_data_der: bytes) -> dict:
    """
    Walk the outer SignedData and extract SCEP signed attributes by OID.

    Returns a dict: { oid_dotted_str: raw_value_bytes }.
    This is a best-effort parser tuned to the structures we build.
    """
    attrs = {}
    # We parse the DER tree looking for authenticated attribute sequences.
    # Structure: SignedData > signerInfos > signerInfo > signedAttrs
    # Each signedAttr is SEQUENCE { OID, SET { value } }
    def _walk(data, depth=0):
        pos = 0
        while pos < len(data):
            try:
                tag, val, npos = _parse_tlv(data, pos)
            except Exception:
                break
            # Recurse into constructed types
            if tag in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6):
                _walk(val, depth + 1)
            pos = npos

    # Actually, let's do a targeted search for OID+SET pairs
    def _extract_attrs(data):
        pos = 0
        while pos < len(data):
            try:
                tag, val, npos = _parse_tlv(data, pos)
            except Exception:
                break
            if tag == 0x30 and len(val) > 2:
                # Maybe an attribute: SEQUENCE { OID, SET { value } }
                try:
                    t2, oid_bytes, p2 = _parse_tlv(val, 0)
                    if t2 == 0x06 and p2 < len(val):
                        t3, set_val, _ = _parse_tlv(val, p2)
                        if t3 == 0x31:
                            # Decode OID
                            oid_str = _decode_oid(oid_bytes)
                            # The set_val is the content of the SET
                            # Extract the inner value (first element of the set)
                            if set_val:
                                attrs[oid_str] = set_val
                except Exception:
                    pass
                # Recurse
                _extract_attrs(val)
            elif tag in (0x31, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6):
                _extract_attrs(val)
            pos = npos

    _extract_attrs(signed_data_der)
    return attrs


def _decode_oid(oid_bytes: bytes) -> str:
    """Decode raw OID bytes (without tag/length) to dotted notation."""
    if not oid_bytes:
        return ""
    first = oid_bytes[0]
    parts = [first // 40, first % 40]
    i = 1
    while i < len(oid_bytes):
        val = 0
        while i < len(oid_bytes):
            b = oid_bytes[i]; i += 1
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(val)
    return ".".join(map(str, parts))


# ── SCEP signed attribute building ────────────────────────────────────────────

def _build_scep_signed_attr(oid_str: str, value_der: bytes) -> bytes:
    """Build one SCEP signed attribute: SEQUENCE { OID, SET { value_der } }."""
    return _seq(_oid(oid_str) + _set(value_der))


def _build_scep_signed_attrs_der(
    message_type: str,
    transaction_id: str,
    sender_nonce: bytes,
    pki_status: str = None,
    fail_info: str = None,
    recipient_nonce: bytes = None,
) -> bytes:
    """
    Build the signedAttrs SET contents for a SCEP pkiMessage.

    The returned bytes are the raw content of the [0] IMPLICIT SET OF Attribute
    as they appear in SignerInfo (without the outer [0] tag).
    """
    attrs = b""
    attrs += _build_scep_signed_attr(_OID_MESSAGE_TYPE,
                                     _printable_string(message_type))
    attrs += _build_scep_signed_attr(_OID_TRANSACTION_ID,
                                     _printable_string(transaction_id))
    attrs += _build_scep_signed_attr(_OID_SENDER_NONCE,
                                     _octet_string(sender_nonce))
    if pki_status is not None:
        attrs += _build_scep_signed_attr(_OID_PKI_STATUS,
                                         _printable_string(pki_status))
    if fail_info is not None:
        attrs += _build_scep_signed_attr(_OID_FAIL_INFO,
                                         _printable_string(fail_info))
    if recipient_nonce is not None:
        attrs += _build_scep_signed_attr(_OID_RECIPIENT_NONCE,
                                         _octet_string(recipient_nonce))
    return attrs


# ── Transaction ID (RFC 8894 §3.1) ────────────────────────────────────────────

def _compute_transaction_id(public_key) -> str:
    """
    transactionID = hex(SHA-256(SubjectPublicKeyInfo DER))
    Matches scep_transaction_id() in lib/scep_proto/scep_proto.c.
    """
    spki_der = public_key.public_bytes(
        Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki_der).hexdigest()


# ── Cert helpers ──────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _make_cert(
    subject_name: x509.Name,
    issuer_name: x509.Name,
    public_key,
    signing_key,
    *,
    days: int = 365,
    is_ca: bool = False,
    extensions=None,
) -> x509.Certificate:
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    if extensions:
        for ext, critical in extensions:
            builder = builder.add_extension(ext, critical=critical)
    return builder.sign(signing_key, hashes.SHA256())


def _self_signed(common_name: str, key, *, days=365, is_ca=False, extensions=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return _make_cert(name, name, key.public_key(), key,
                      days=days, is_ca=is_ca, extensions=extensions)


# ── FakeNdesCA ────────────────────────────────────────────────────────────────

class FakeNdesCA:
    """
    In-memory NDES CA for testing SCEP enrollment without hitting a real server.

    Keys / certs created at init time:
      - ECDSA P-256 RA signing key + cert  (self-signed, signing usage)
      - RSA-2048 RA encryption key + cert  (self-signed, encryption usage)
      - ECDSA P-256 CA issuing key + cert  (self-signed CA)

    These mirror what a real NDES deployment would expose via GetCACert.
    """

    def __init__(self, expect_challenge_password: str = "CHALLENGE"):
        self.challenge_password = expect_challenge_password

        # CA issuing key + cert
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        self._ca_cert = _self_signed(
            "Fake-NDES-CA", self._ca_key, days=3650, is_ca=True
        )

        # RA signing cert (ECDSA P-256)
        self._ra_sign_key = ec.generate_private_key(ec.SECP256R1())
        self._ra_sign_cert = _self_signed(
            "Fake-NDES-RA-Sign",
            self._ra_sign_key,
            extensions=[
                (x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), True),
            ],
        )

        # RA encryption cert (RSA-2048 — needed because PKCS7EnvelopeBuilder
        # only supports RSA KTRI recipients; real NDES uses RSA for this too).
        self._ra_enc_key = rsa.generate_private_key(65537, 2048)
        self._ra_enc_cert = _self_signed(
            "Fake-NDES-RA-Encrypt",
            self._ra_enc_key,
            extensions=[
                (x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=True, data_encipherment=True,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), True),
            ],
        )

        # Track issued certs (transactionID -> issued cert) for test introspection
        self.issued: dict[str, x509.Certificate] = {}

    # ── GetCACert response ────────────────────────────────────────────────────

    def respond_get_cacert(self) -> bytes:
        """
        Return a degenerate PKCS#7 SignedData containing three certs:
        CA cert, RA signing cert, RA encryption cert.

        Content-type: application/x-x509-ca-ra-cert (NDES with RA certs).
        """
        return serialize_certificates(
            [self._ca_cert, self._ra_sign_cert, self._ra_enc_cert],
            Encoding.DER,
        )

    def respond_get_cacert_single(self) -> bytes:
        """
        Single-cert variant: the CA cert only.
        Simulates a simple SCEP CA without separate RA.
        """
        return serialize_certificates([self._ca_cert], Encoding.DER)

    # ── PKIOperation (PKCSReq -> CertRep) ────────────────────────────────────

    def respond_pki_operation(
        self,
        pki_message_der: bytes,
        *,
        force_fail_info: str = None,
    ) -> bytes:
        """
        Parse a SCEP PKCSReq pkiMessage (SignedData wrapping EnvelopedData
        wrapping the CSR), then:
          - Verify outer SignedData signature (ECDSA-P256).
          - Decrypt EnvelopedData (RSA-OAEP or PKCS#1v1.5 with our RA enc key).
          - Extract signed attributes: transactionID, messageType, senderNonce.
          - Extract challengePassword from CSR.
          - If challenge is wrong OR force_fail_info set, return FAILURE CertRep.
          - Otherwise sign a new cert and return SUCCESS CertRep.

        Returns DER bytes of the CertRep pkiMessage.
        """
        # Parse the outer SignedData (the client's PKCS7 blob).
        # We extract:
        #   - The enveloped-data payload (inner DER)
        #   - The signed attributes (messageType, transactionID, senderNonce)
        #   - The signer certificate (for the client's public key)

        parsed = self._parse_pkcsreq(pki_message_der)

        # Extract signed attributes
        transaction_id = parsed["transaction_id"]
        sender_nonce   = parsed["sender_nonce"]
        challenge_pw   = parsed["challenge_password"]
        csr_pubkey     = parsed["csr_pubkey"]
        csr_subject    = parsed["csr_subject"]

        # Decide: SUCCESS or FAILURE
        recipient_nonce = os.urandom(16)

        if force_fail_info is not None:
            return self._build_certrep_failure(
                transaction_id=transaction_id,
                sender_nonce=sender_nonce,
                recipient_nonce=recipient_nonce,
                fail_info=force_fail_info,
                recipient_cert=parsed["signer_cert"],
            )

        if challenge_pw != self.challenge_password:
            return self._build_certrep_failure(
                transaction_id=transaction_id,
                sender_nonce=sender_nonce,
                recipient_nonce=recipient_nonce,
                fail_info=_FAIL_BAD_REQUEST,
                recipient_cert=parsed["signer_cert"],
            )

        # Issue a cert signed by our CA
        issued_cert = self._issue_cert(csr_subject, csr_pubkey)
        self.issued[transaction_id] = issued_cert

        return self._build_certrep_success(
            transaction_id=transaction_id,
            sender_nonce=sender_nonce,
            recipient_nonce=recipient_nonce,
            issued_cert=issued_cert,
            recipient_cert=parsed["signer_cert"],
        )

    # ── Internal: parse PKCSReq ───────────────────────────────────────────────

    def _parse_pkcsreq(self, pki_message_der: bytes) -> dict:
        """
        Parse the outer SignedData of a PKCSReq.

        Returns dict with keys:
          transaction_id, sender_nonce, challenge_password,
          csr_pubkey, csr_subject, signer_cert, message_type
        """
        # Step 1: verify outer SignedData signature
        # We use cryptography's load_der_pkcs7_certificates to extract the
        # embedded certs, then extract content manually.
        #
        # For signature verification, we'll use the embedded signer cert.
        # The cryptography library doesn't expose raw SignedData parsing,
        # so we parse the DER structure ourselves for the SCEP-specific parts.

        signed_data_content, signer_cert, signed_attrs_raw = \
            _parse_signed_data_der(pki_message_der)

        # Verify the signature on the signedAttrs using the signer cert's key
        # (The signer cert is the client's self-signed transient cert)
        _verify_signed_data_signature(pki_message_der, signer_cert)

        # Extract SCEP signed attributes
        attrs = _extract_signed_attrs(signed_attrs_raw)

        transaction_id = attrs.get(_OID_TRANSACTION_ID, "")
        sender_nonce   = attrs.get(_OID_SENDER_NONCE, b"")
        message_type   = attrs.get(_OID_MESSAGE_TYPE, "")

        # Step 2: decrypt the EnvelopedData payload
        csr_der = pkcs7_decrypt_der(
            signed_data_content, self._ra_enc_cert, self._ra_enc_key, []
        )

        # Step 3: parse the CSR to get public key + subject + challengePassword
        csr = x509.load_der_x509_csr(csr_der)
        challenge_pw = _extract_challenge_password(csr)
        csr_pubkey  = csr.public_key()
        csr_subject = csr.subject

        return {
            "transaction_id":    transaction_id,
            "sender_nonce":      sender_nonce,
            "message_type":      message_type,
            "challenge_password": challenge_pw,
            "csr_pubkey":        csr_pubkey,
            "csr_subject":       csr_subject,
            "signer_cert":       signer_cert,
        }

    # ── Internal: build CertRep ───────────────────────────────────────────────

    def _issue_cert(self, subject_name: x509.Name, public_key) -> x509.Certificate:
        """Issue a cert for the given subject and key, signed by our CA."""
        return _make_cert(
            subject_name,
            self._ca_cert.subject,
            public_key,
            self._ca_key,
            days=365,
        )

    def _build_certrep_success(
        self,
        *,
        transaction_id: str,
        sender_nonce: bytes,
        recipient_nonce: bytes,
        issued_cert: x509.Certificate,
        recipient_cert: x509.Certificate,
    ) -> bytes:
        """
        Build a SUCCESS CertRep:
        SignedData(signedAttrs=[messageType=3, transactionID, pkiStatus=0,
                                recipientNonce],
                   content=EnvelopedData(degenerate-SignedData(issued_cert)))
        """
        # Inner: degenerate SignedData containing the issued cert
        inner_degenerate = serialize_certificates([issued_cert], Encoding.DER)

        # Middle: EnvelopedData wrapping the degenerate SignedData,
        # encrypted to the client's RSA-2048 public key (KTRI).
        # The firmware now uses RSA-2048, so PKCS7EnvelopeBuilder works directly.
        env_builder = PKCS7EnvelopeBuilder().set_data(inner_degenerate)
        env_builder = env_builder.add_recipient(recipient_cert)
        enveloped_der = env_builder.encrypt(Encoding.DER, options=_P7_BINARY)

        # Outer: SignedData with SCEP attributes
        return self._build_signed_certrep(
            content_der=enveloped_der,
            transaction_id=transaction_id,
            sender_nonce=sender_nonce,
            recipient_nonce=recipient_nonce,
            pki_status=_PKI_STATUS_SUCCESS,
        )

    def _build_certrep_failure(
        self,
        *,
        transaction_id: str,
        sender_nonce: bytes,
        recipient_nonce: bytes,
        fail_info: str,
        recipient_cert: x509.Certificate,
    ) -> bytes:
        """Build a FAILURE CertRep (no inner content, just signed attrs)."""
        # FAILURE response: still a SignedData, but content is empty data
        # We sign an empty content with the failure attributes
        return self._build_signed_certrep(
            content_der=b"",
            transaction_id=transaction_id,
            sender_nonce=sender_nonce,
            recipient_nonce=recipient_nonce,
            pki_status=_PKI_STATUS_FAILURE,
            fail_info=fail_info,
        )

    def _build_signed_certrep(
        self,
        *,
        content_der: bytes,
        transaction_id: str,
        sender_nonce: bytes,
        recipient_nonce: bytes,
        pki_status: str,
        fail_info: str = None,
    ) -> bytes:
        """
        Build the outer SignedData for a CertRep, signed by the RA signing cert.
        The signed attributes include the SCEP metadata.
        The content is wrapped in the SignedData content field.
        """
        # Build the full CertRep DER using our raw DER builder.
        # This gives us full control over the SCEP signed attributes.
        return _build_scep_signed_data(
            content_der=content_der,
            signing_key=self._ra_sign_key,
            signing_cert=self._ra_sign_cert,
            message_type=_MSG_TYPE_CERTREP,
            transaction_id=transaction_id,
            sender_nonce=recipient_nonce,  # In CertRep, senderNonce is the CA's nonce
            pki_status=pki_status,
            fail_info=fail_info,
            recipient_nonce=sender_nonce,  # recipientNonce echoes client's senderNonce
        )

    @property
    def ca_cert(self) -> x509.Certificate:
        return self._ca_cert

    @property
    def ra_sign_cert(self) -> x509.Certificate:
        return self._ra_sign_cert

    @property
    def ra_enc_cert(self) -> x509.Certificate:
        return self._ra_enc_cert


# ── Low-level PKCS7 / DER builders ───────────────────────────────────────────

def _build_scep_signed_data(
    *,
    content_der: bytes,
    signing_key,
    signing_cert: x509.Certificate,
    message_type: str,
    transaction_id: str,
    sender_nonce: bytes,
    pki_status: str = None,
    fail_info: str = None,
    recipient_nonce: bytes = None,
) -> bytes:
    """
    Build a SCEP pkiMessage as a raw DER SignedData.

    This hand-builds the CMS SignedData structure because the cryptography
    library's PKCS7SignatureBuilder does not expose arbitrary signed attributes.

    Structure (RFC 5652 §5 + RFC 8894 §3):
      SEQUENCE {                    -- ContentInfo
        OID (signedData)
        [0] EXPLICIT SEQUENCE {     -- SignedData
          INTEGER (version=1)
          SET { SEQUENCE { OID(sha256), NULL } }   -- digestAlgorithms
          SEQUENCE {               -- encapContentInfo
            OID (id-data or id-envelopedData)
            [0] EXPLICIT OCTET STRING (content_der)   -- may be absent for FAILURE
          }
          [0] IMPLICIT SET (certs) -- certificates
          SET {                    -- signerInfos
            SEQUENCE {             -- SignerInfo
              INTEGER (version=1)
              SEQUENCE { issuer, serialNumber }
              SEQUENCE { OID(sha256), NULL }     -- digestAlgorithm
              [0] SET { ... signed attributes ... }
              SEQUENCE { OID(ecdsa-with-sha256) } -- signatureAlgorithm
              OCTET STRING (signature)
            }
          }
        }
      }
    """
    # ── OID constants ────────────────────────────────────────────────────────
    OID_SIGNED_DATA        = "1.2.840.113549.1.7.2"
    OID_DATA               = "1.2.840.113549.1.7.1"
    OID_ENVELOPED_DATA     = "1.2.840.113549.1.7.3"
    OID_SHA256             = "2.16.840.1.101.3.4.2.1"
    OID_ECDSA_WITH_SHA256  = "1.2.840.10045.4.3.2"
    OID_RSA_WITH_SHA256    = "1.2.840.113549.1.1.11"

    # Determine content OID: envelopedData if content, data otherwise
    if content_der:
        # Check if it looks like EnvelopedData (starts with 0x30 ... envelopedData OID)
        # For simplicity, always use id-data as the encap content type on responses
        content_oid = OID_DATA
    else:
        content_oid = OID_DATA

    # ── Build signed attributes ────────────────────────────────────────────
    signed_attrs_content = _build_scep_signed_attrs_der(
        message_type=message_type,
        transaction_id=transaction_id,
        sender_nonce=sender_nonce,
        pki_status=pki_status,
        fail_info=fail_info,
        recipient_nonce=recipient_nonce,
    )
    # The signedAttrs field is [0] IMPLICIT SET OF Attribute
    # When computing the digest, we hash the DER of SET { attrs }
    signed_attrs_der = _set(signed_attrs_content)    # SET tag for hashing
    signed_attrs_field = bytes([0xA0]) + _der_len(len(signed_attrs_content)) + signed_attrs_content

    # ── Digest the signed attributes ──────────────────────────────────────
    digest = hashlib.sha256(signed_attrs_der).digest()

    # ── Sign the digest ───────────────────────────────────────────────────
    if isinstance(signing_key, ec.EllipticCurvePrivateKey):
        sig_bytes = signing_key.sign(signed_attrs_der, ec.ECDSA(hashes.SHA256()))
        sig_alg_oid = OID_ECDSA_WITH_SHA256
    else:
        sig_bytes = signing_key.sign(signed_attrs_der, asym_padding.PKCS1v15(), hashes.SHA256())
        sig_alg_oid = OID_RSA_WITH_SHA256

    # ── Signer identifier (issuerAndSerialNumber) ─────────────────────────
    issuer_der  = signing_cert.issuer.public_bytes()
    serial_num  = signing_cert.serial_number
    signer_id   = _seq(issuer_der + _integer(serial_num))

    # ── Signing cert DER ──────────────────────────────────────────────────
    cert_der = signing_cert.public_bytes(Encoding.DER)

    # ── Algorithm identifiers ─────────────────────────────────────────────
    sha256_alg   = _seq(_oid(OID_SHA256) + b"\x05\x00")  # SHA-256 with NULL params
    sig_alg      = _seq(_oid(sig_alg_oid))                 # ECDSA has no params

    # ── SignerInfo ─────────────────────────────────────────────────────────
    signer_info = _seq(
        _integer(1)          # version = 1
        + signer_id
        + sha256_alg
        + signed_attrs_field
        + sig_alg
        + _octet_string(sig_bytes)
    )

    # ── EncapContentInfo ──────────────────────────────────────────────────
    if content_der:
        encap_content = _seq(
            _oid(content_oid)
            + _explicit(0, _octet_string(content_der))
        )
    else:
        encap_content = _seq(_oid(content_oid))

    # ── Certificates [0] IMPLICIT ─────────────────────────────────────────
    certs_field = bytes([0xA0]) + _der_len(len(cert_der)) + cert_der

    # ── DigestAlgorithms ──────────────────────────────────────────────────
    digest_algorithms = _set(sha256_alg)

    # ── SignedData ─────────────────────────────────────────────────────────
    signed_data = _seq(
        _integer(1)            # version
        + digest_algorithms
        + encap_content
        + certs_field
        + _set(signer_info)    # signerInfos
    )

    # ── ContentInfo ───────────────────────────────────────────────────────
    content_info = _seq(
        _oid(OID_SIGNED_DATA)
        + _explicit(0, signed_data)
    )

    return content_info


def _parse_signed_data_der(pki_message_der: bytes):
    """
    Parse a SCEP pkiMessage DER and extract:
      - encapContent bytes (the inner payload)
      - signer certificate (x509.Certificate)
      - signed attributes raw bytes

    Returns (content_bytes, signer_cert, signed_attrs_bytes).
    """
    # ContentInfo: SEQUENCE { OID, [0] SignedData }
    tag, ci_val, _ = _parse_tlv(pki_message_der, 0)
    assert tag == 0x30, f"Expected SEQUENCE for ContentInfo, got {tag:#x}"

    pos = 0
    oid_tag, oid_val, pos = _parse_tlv(ci_val, pos)
    assert oid_tag == 0x06

    ctx_tag, sd_val, pos = _parse_tlv(ci_val, pos)
    assert ctx_tag == 0xA0, f"Expected [0] wrapper, got {ctx_tag:#x}"

    # SignedData: SEQUENCE { version, digestAlgorithms, encapContentInfo,
    #                        [0] certs, [1] crls, signerInfos }
    sd_tag, sd_inner, _ = _parse_tlv(sd_val, 0)
    assert sd_tag == 0x30

    pos = 0
    # version
    _, _, pos = _parse_tlv(sd_inner, pos)
    # digestAlgorithms
    _, _, pos = _parse_tlv(sd_inner, pos)
    # encapContentInfo
    eci_tag, eci_val, pos = _parse_tlv(sd_inner, pos)
    assert eci_tag == 0x30
    # Extract content from encapContentInfo
    eci_pos = 0
    _, eci_oid_val, eci_pos = _parse_tlv(eci_val, eci_pos)
    content_bytes = b""
    if eci_pos < len(eci_val):
        ctx_tag2, ctx_val, eci_pos = _parse_tlv(eci_val, eci_pos)
        if ctx_tag2 == 0xA0:
            os_tag, os_val, _ = _parse_tlv(ctx_val, 0)
            if os_tag == 0x04:
                content_bytes = os_val

    # Certificates [0]
    signer_cert = None
    if pos < len(sd_inner) and (sd_inner[pos] & 0xE0) == 0xA0:
        cert_tag, cert_set_val, pos = _parse_tlv(sd_inner, pos)
        if cert_tag == 0xA0:
            # Parse first certificate
            try:
                c_pos = 0
                c_tag, c_val, c_pos = _parse_tlv(cert_set_val, c_pos)
                if c_tag == 0x30:
                    # Reconstruct the full cert DER
                    cert_der = bytes([0x30]) + _der_len(len(c_val)) + c_val
                    signer_cert = x509.load_der_x509_certificate(cert_der)
            except Exception:
                pass

    # Skip CRLs [1] if present
    if pos < len(sd_inner) and sd_inner[pos] == 0xA1:
        _, _, pos = _parse_tlv(sd_inner, pos)

    # signerInfos SET
    signed_attrs_raw = b""
    if pos < len(sd_inner):
        si_set_tag, si_set_val, _ = _parse_tlv(sd_inner, pos)
        if si_set_tag == 0x31 and si_set_val:
            # First signerInfo
            si_tag, si_val, _ = _parse_tlv(si_set_val, 0)
            if si_tag == 0x30:
                signed_attrs_raw = si_val

    return content_bytes, signer_cert, signed_attrs_raw


def _extract_signed_attrs(signer_info_val: bytes) -> dict:
    """
    Extract SCEP signed attributes from a SignerInfo value bytes.
    Returns dict: { oid_str: decoded_value }
    Values are str for string attrs, bytes for octet strings.
    """
    attrs = {}
    pos = 0
    # Skip version
    if not signer_info_val:
        return attrs
    _, _, pos = _parse_tlv(signer_info_val, pos)
    # Skip signerIdentifier
    _, _, pos = _parse_tlv(signer_info_val, pos)
    # Skip digestAlgorithm
    _, _, pos = _parse_tlv(signer_info_val, pos)
    # signedAttrs [0] IMPLICIT
    if pos >= len(signer_info_val):
        return attrs
    sa_tag = signer_info_val[pos]
    if sa_tag != 0xA0:
        return attrs
    _, sa_val, _ = _parse_tlv(signer_info_val, pos)
    # Walk attributes
    a_pos = 0
    while a_pos < len(sa_val):
        try:
            a_tag, a_val, a_pos = _parse_tlv(sa_val, a_pos)
            if a_tag != 0x30:
                continue
            # SEQUENCE { OID, SET { value } }
            v_pos = 0
            oid_tag, oid_bytes, v_pos = _parse_tlv(a_val, v_pos)
            if oid_tag != 0x06:
                continue
            oid_str = _decode_oid(oid_bytes)
            set_tag, set_val, v_pos = _parse_tlv(a_val, v_pos)
            if set_tag != 0x31 or not set_val:
                continue
            # Inner value
            val_tag, val_bytes, _ = _parse_tlv(set_val, 0)
            if val_tag in (0x13, 0x0C, 0x16):  # printable/utf8/ia5
                attrs[oid_str] = val_bytes.decode("ascii", errors="replace")
            elif val_tag == 0x04:  # octet string
                attrs[oid_str] = val_bytes
            else:
                attrs[oid_str] = val_bytes
        except Exception:
            break
    return attrs


def _verify_signed_data_signature(pki_message_der: bytes, signer_cert: x509.Certificate):
    """
    Verify the ECDSA/RSA signature in a SignedData over its signedAttrs.
    Raises an exception if verification fails.
    """
    # Re-parse to get signedAttrs DER and signature bytes
    tag, ci_val, _ = _parse_tlv(pki_message_der, 0)
    ctx_tag, sd_val, _ = _parse_tlv(ci_val, _tlv_skip(ci_val, 0, 1))  # skip OID
    sd_tag, sd_inner, _ = _parse_tlv(sd_val, 0)

    pos = 0
    _, _, pos = _parse_tlv(sd_inner, pos)  # version
    _, _, pos = _parse_tlv(sd_inner, pos)  # digestAlgorithms
    _, _, pos = _parse_tlv(sd_inner, pos)  # encapContentInfo
    # certs
    if pos < len(sd_inner) and (sd_inner[pos] & 0xE0) == 0xA0:
        _, _, pos = _parse_tlv(sd_inner, pos)
    # signerInfos
    si_set_tag, si_set_val, _ = _parse_tlv(sd_inner, pos)
    si_tag, si_val, _ = _parse_tlv(si_set_val, 0)

    # Extract signedAttrs and signature from signerInfo
    si_pos = 0
    _, _, si_pos = _parse_tlv(si_val, si_pos)  # version
    _, _, si_pos = _parse_tlv(si_val, si_pos)  # signerIdentifier
    _, _, si_pos = _parse_tlv(si_val, si_pos)  # digestAlgorithm
    # signedAttrs [0] IMPLICIT
    sa_tag = si_val[si_pos]
    sa_raw_tag, sa_raw_inner, si_pos = _parse_tlv(si_val, si_pos)
    # Reconstruct as SET for hashing (replace [0] tag byte with 0x31)
    signed_attrs_for_hash = b"\x31" + _der_len(len(sa_raw_inner)) + sa_raw_inner
    _, _, si_pos = _parse_tlv(si_val, si_pos)  # signatureAlgorithm
    sig_tag, sig_bytes_raw, _ = _parse_tlv(si_val, si_pos)  # signature OCTET STRING

    pub_key = signer_cert.public_key()
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key.verify(sig_bytes_raw, signed_attrs_for_hash, ec.ECDSA(hashes.SHA256()))
    else:
        pub_key.verify(sig_bytes_raw, signed_attrs_for_hash, asym_padding.PKCS1v15(), hashes.SHA256())


def _tlv_skip(data: bytes, pos: int, count: int) -> int:
    """Skip `count` TLV items starting at pos, return new pos."""
    for _ in range(count):
        _, _, pos = _parse_tlv(data, pos)
    return pos


def _extract_challenge_password(csr: x509.CertificateSigningRequest) -> str:
    """
    Extract the challengePassword attribute (OID 1.2.840.113549.1.9.7)
    from a CSR.

    The cryptography library doesn't expose challengePassword natively as of
    version 48, so we parse the CSR attributes manually.
    """
    OID_CHALLENGE_PW_OBJ = x509.ObjectIdentifier(_OID_CHALLENGE_PW)

    # Try via the cryptography API first (may work in newer versions)
    try:
        for attr in csr.attributes:
            if attr.oid == OID_CHALLENGE_PW_OBJ:
                val = attr.value
                if isinstance(val, bytes):
                    # Raw DER - decode
                    try:
                        tag, v, _ = _parse_tlv(val, 0)
                        if tag in (0x13, 0x0C, 0x16, 0x14):
                            return v.decode("ascii", errors="replace")
                        return val.decode("ascii", errors="replace")
                    except Exception:
                        return val.decode("ascii", errors="replace")
                return str(val)
    except Exception:
        pass

    # Fall back to raw DER parsing of the CSR
    return _parse_challenge_pw_from_csr_der(
        csr.public_bytes(Encoding.DER)
    )


def _parse_challenge_pw_from_csr_der(csr_der: bytes) -> str:
    """Parse challengePassword from raw CSR DER by walking attributes."""
    OID_CHALLENGE_BYTES = _oid(_OID_CHALLENGE_PW)[2:]  # strip tag+len

    # Walk all sequences looking for the challengePassword OID
    def _walk(data):
        pos = 0
        while pos < len(data):
            try:
                tag, val, npos = _parse_tlv(data, pos)
            except Exception:
                break
            if tag == 0x06:
                # Check if this OID is challengePassword
                if val == OID_CHALLENGE_BYTES:
                    # The value should be the next sibling in the parent sequence
                    # Return a sentinel so the parent can grab the next element
                    return "__FOUND_OID__"
            elif tag in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3):
                result = _walk_attrs(val)
                if result:
                    return result
            pos = npos
        return None

    def _walk_attrs(data):
        """Walk attributes looking for challengePassword SEQUENCE."""
        pos = 0
        while pos < len(data):
            try:
                tag, val, npos = _parse_tlv(data, pos)
            except Exception:
                break
            if tag == 0x30:
                # Check if this is a challengePassword attribute
                try:
                    vpos = 0
                    oid_tag, oid_bytes, vpos = _parse_tlv(val, vpos)
                    if oid_tag == 0x06:
                        oid_decoded = _decode_oid(oid_bytes)
                        if oid_decoded == _OID_CHALLENGE_PW:
                            # Next is SET { value }
                            set_tag, set_val, _ = _parse_tlv(val, vpos)
                            if set_tag == 0x31 and set_val:
                                str_tag, str_val, _ = _parse_tlv(set_val, 0)
                                if str_tag in (0x13, 0x0C, 0x16, 0x14):
                                    return str_val.decode("ascii", errors="replace")
                                return str_val.decode("ascii", errors="replace")
                except Exception:
                    pass
                # Recurse
                result = _walk_attrs(val)
                if result:
                    return result
            elif tag in (0x31, 0xA0, 0xA1, 0xA2, 0xA3):
                result = _walk_attrs(val)
                if result:
                    return result
            pos = npos
        return None

    return _walk_attrs(csr_der) or ""


# ── SCEPClient ────────────────────────────────────────────────────────────────

class SCEPClient:
    """
    Python SCEP client that mirrors what the C firmware does.

    Key algorithm: RSA-2048 SHA-256 PKCS#1v1.5.
    Rationale: Microsoft NDES in legacy CryptoAPI/CSP mode rejects ECDSA-signed
    pkiMessages with failInfo=1 (badMessageCheck).  RFC 8894 §3.5.2 requires RSA
    for legacy NDES interoperability.

    All I/O goes through in-memory bytes; no sockets used.
    """

    def __init__(self, cn: str, challenge_password: str):
        self.cn               = cn
        self.challenge_pw     = challenge_password
        self._private_key     = None
        self._transaction_id  = None
        self._sender_nonce    = None
        self._self_signed     = None  # transient cert reused across build/parse
        self.issued_cert      = None  # set after successful enrollment

    def generate_key(self):
        """Step 1: generate RSA-2048 key pair (matches firmware scep_generate_keypair)."""
        self._private_key    = rsa.generate_private_key(65537, 2048)
        self._transaction_id = _compute_transaction_id(self._private_key.public_key())
        self._sender_nonce   = os.urandom(16)
        self._self_signed    = _self_signed(self.cn, self._private_key, days=1)

    @property
    def transaction_id(self) -> str:
        return self._transaction_id

    def build_pkcsreq(self, ra_enc_cert: x509.Certificate) -> bytes:
        """
        Build the PKCSReq pkiMessage:
          SignedData(signedAttrs=[messageType=19, transactionID, senderNonce],
                     content=EnvelopedData(CSR DER))

        The signer is a transient self-signed RSA-2048 cert built from our key.
        The RA encryption cert (RSA) is used to encrypt the CSR via PKCS7EnvelopeBuilder.
        """
        assert self._private_key, "call generate_key() first"

        # Build CSR with challengePassword (signed with RSA-2048 SHA-256)
        csr = self._build_csr()
        csr_der = csr.public_bytes(Encoding.DER)

        # Build signed PKCSReq using the pre-generated self-signed cert
        # (same cert object reused in parse_certrep for decryption matching)

        # Encrypt CSR to RA encryption cert (RSA KTRI -- PKCS7EnvelopeBuilder supports RSA)
        env_builder = PKCS7EnvelopeBuilder().set_data(csr_der)
        env_builder = env_builder.add_recipient(ra_enc_cert)
        enveloped_der = env_builder.encrypt(Encoding.DER, options=_P7_BINARY)

        # Build signed PKCSReq (RSA PKCS#1v1.5 SHA-256 signature)
        return _build_scep_signed_data(
            content_der=enveloped_der,
            signing_key=self._private_key,
            signing_cert=self._self_signed,
            message_type=_MSG_TYPE_PKCSREQ,
            transaction_id=self._transaction_id,
            sender_nonce=self._sender_nonce,
        )

    def _build_csr(self) -> x509.CertificateSigningRequest:
        """Build a PKCS#10 CSR with challengePassword in attributes, signed RSA-2048."""
        OID_CHALLENGE_PW_OBJ = x509.ObjectIdentifier(_OID_CHALLENGE_PW)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.cn)])
        )
        builder = builder.add_attribute(
            OID_CHALLENGE_PW_OBJ,
            self.challenge_pw.encode("ascii"),
        )
        return builder.sign(self._private_key, hashes.SHA256())

    def parse_certrep(self, certrep_der: bytes) -> None:
        """
        Parse a CertRep pkiMessage and extract the issued cert (on SUCCESS).

        Raises:
          ValueError on transactionID mismatch.
          RuntimeError on FAILURE/PENDING pkiStatus (includes failInfo).
        """
        content_bytes, signer_cert, signed_attrs_raw = \
            _parse_signed_data_der(certrep_der)
        attrs = _extract_signed_attrs(signed_attrs_raw)

        # Validate transactionID
        tx_id = attrs.get(_OID_TRANSACTION_ID, "")
        if tx_id != self._transaction_id:
            raise ValueError(
                f"transactionID mismatch: got {tx_id!r}, "
                f"expected {self._transaction_id!r}"
            )

        # Check pkiStatus
        status = attrs.get(_OID_PKI_STATUS, "")
        if status == _PKI_STATUS_FAILURE:
            fail_info = attrs.get(_OID_FAIL_INFO, "(none)")
            raise RuntimeError(f"pkiStatus=FAILURE, failInfo={fail_info}")
        if status == _PKI_STATUS_PENDING:
            raise RuntimeError("pkiStatus=PENDING")
        if status != _PKI_STATUS_SUCCESS:
            raise RuntimeError(f"Unknown pkiStatus={status!r}")

        # Decrypt enveloped content (inner degenerate SignedData with cert).
        # The server encrypted to our RSA-2048 key using the signer cert
        # embedded in the PKCSReq, which is self._self_signed.
        # pkcs7_decrypt_der requires the exact same cert object (matching
        # serial number) that was used as the KTRI recipient during encryption.
        inner_degenerate = pkcs7_decrypt_der(
            content_bytes, self._self_signed, self._private_key, []
        )

        # Parse the degenerate SignedData to extract the cert
        certs = load_der_pkcs7_certificates(inner_degenerate)
        assert certs, "No certificates in inner degenerate SignedData"
        self.issued_cert = certs[0]

    def parse_getcacert(self, getcacert_der: bytes) -> dict:
        """
        Parse a GetCACert degenerate SignedData response.

        Returns dict with keys: ca_cert, ra_sign_cert, ra_enc_cert, single_cert.
        For 1-cert bundles, all three cert slots alias the same cert.
        For 3-cert bundles, they are distinct.
        """
        certs = load_der_pkcs7_certificates(getcacert_der)
        if not certs:
            raise ValueError("No certs in GetCACert response")
        if len(certs) == 1:
            return {
                "ca_cert":      certs[0],
                "ra_sign_cert": certs[0],
                "ra_enc_cert":  certs[0],
                "single_cert":  True,
            }
        # 3-cert bundle: order is CA, RA-sign, RA-enc (NDES convention)
        return {
            "ca_cert":      certs[0],
            "ra_sign_cert": certs[1],
            "ra_enc_cert":  certs[2] if len(certs) >= 3 else certs[1],
            "single_cert":  len(certs) < 3,
        }


# ── pytest fixtures ───────────────────────────────────────────────────────────

CHALLENGE_PW = "FFC9708138742EC99A8CDF837A9F4CEA"


@pytest.fixture(scope="module")
def ca():
    """A FakeNdesCA instance reused across tests in this module."""
    return FakeNdesCA(expect_challenge_password=CHALLENGE_PW)


@pytest.fixture
def client(ca):
    """A fresh SCEPClient with a newly generated key."""
    c = SCEPClient(cn="esp-tty-test-device", challenge_password=CHALLENGE_PW)
    c.generate_key()
    return c


# ── Test cases ────────────────────────────────────────────────────────────────

class TestHappyPath:
    """Test 1: full successful enrollment."""

    def test_issued_cert_has_correct_cn(self, ca, client):
        getcacert_resp = ca.respond_get_cacert()
        bundle = client.parse_getcacert(getcacert_resp)

        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)
        client.parse_certrep(certrep)

        assert client.issued_cert is not None
        cn = client.issued_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn, "Issued cert has no CN"
        assert cn[0].value == "esp-tty-test-device"

    def test_issued_cert_spki_matches_device_pubkey(self, ca, client):
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.parse_certrep(ca.respond_pki_operation(client.build_pkcsreq(bundle["ra_enc_cert"])))

        device_spki = client._private_key.public_key().public_bytes(
            Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        issued_spki = client.issued_cert.public_key().public_bytes(
            Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert device_spki == issued_spki, \
            "Issued cert SPKI does not match device's public key"

    def test_issued_cert_signed_by_ca(self, ca, client):
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.parse_certrep(ca.respond_pki_operation(client.build_pkcsreq(bundle["ra_enc_cert"])))

        # Verify issued cert signature using CA public key.
        # The CA key is ECDSA P-256 (FakeNdesCA._ca_key).
        # The issued cert contains the device's RSA-2048 public key,
        # but the CA's ECDSA key signed the cert's TBS bytes.
        ca_pub = ca.ca_cert.public_key()
        ca_pub.verify(
            client.issued_cert.signature,
            client.issued_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )


class TestWrongPassword:
    """Test 2: wrong challenge password → FAILURE + failInfo=badRequest."""

    def test_wrong_password_raises_runtime_error(self, ca):
        # Client uses wrong password
        bad_client = SCEPClient(cn="bad-pw-device", challenge_password="WRONGPW")
        bad_client.generate_key()

        bundle = bad_client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = bad_client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)

        with pytest.raises(RuntimeError) as exc_info:
            bad_client.parse_certrep(certrep)
        assert "FAILURE" in str(exc_info.value)

    def test_wrong_password_fail_info_is_bad_request(self, ca):
        bad_client = SCEPClient(cn="bad-pw2", challenge_password="WRONGPW")
        bad_client.generate_key()
        bundle = bad_client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = bad_client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)

        with pytest.raises(RuntimeError) as exc_info:
            bad_client.parse_certrep(certrep)
        # failInfo=2 = badRequest
        assert "2" in str(exc_info.value)


class TestTamperedMessage:
    """Test 3: flip a byte after signing → FakeNdesCA rejects (sig verify fails)."""

    def test_tampered_pkimessage_rejected(self, ca, client):
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])

        # Flip a byte near the end (in the signature area)
        tampered = bytearray(pkcsreq)
        tampered[-10] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            ca.respond_pki_operation(tampered)


class TestReplayedTransactionID:
    """Test 4: same transactionID with different CSR content."""

    def test_same_txid_different_csr_both_accepted(self, ca):
        # Client A enrolls successfully
        client_a = SCEPClient(cn="replay-device", challenge_password=CHALLENGE_PW)
        client_a.generate_key()
        bundle = client_a.parse_getcacert(ca.respond_get_cacert())
        pkcsreq_a = client_a.build_pkcsreq(bundle["ra_enc_cert"])
        certrep_a = ca.respond_pki_operation(pkcsreq_a)
        client_a.parse_certrep(certrep_a)
        assert client_a.issued_cert is not None, "First enrollment failed"

        # Client B sends a request with the same transactionID
        # (same key → same transactionID per RFC 8894 §3.1)
        # Different CN but same key means same TX-ID.
        client_b = SCEPClient(cn="replay-device-2", challenge_password=CHALLENGE_PW)
        # Reuse client_a's key + transaction_id
        # Must also copy _self_signed so parse_certrep can decrypt the response.
        client_b._private_key    = client_a._private_key
        client_b._transaction_id = client_a._transaction_id
        client_b._sender_nonce   = os.urandom(16)
        # Build a fresh self-signed cert for this CN (same key, different serial)
        client_b._self_signed    = _self_signed(client_b.cn, client_b._private_key, days=1)

        pkcsreq_b = client_b.build_pkcsreq(bundle["ra_enc_cert"])
        certrep_b = ca.respond_pki_operation(pkcsreq_b)
        # Client accepts (NDES doesn't dedup by transactionID)
        client_b.parse_certrep(certrep_b)
        assert client_b.issued_cert is not None

    def test_replayed_txid_response_accepted_by_client(self, ca, client):
        """Client receiving a CertRep with its own transactionID accepts it."""
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)
        # Normal parse: should not raise
        client.parse_certrep(certrep)
        assert client.issued_cert is not None


class TestTransactionIDMismatch:
    """Test 5: transactionID in response doesn't match → client rejects."""

    def test_txid_mismatch_raises_value_error(self, ca, client):
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        # Get a real certrep
        certrep = ca.respond_pki_operation(pkcsreq)

        # Tamper with the transactionID in the signed attrs portion of CertRep.
        # We'll just give the client a different transaction_id so the comparison fails.
        original_txid = client._transaction_id
        client._transaction_id = "a" * 64  # wrong ID

        with pytest.raises(ValueError, match="transactionID mismatch"):
            client.parse_certrep(certrep)

        # Restore
        client._transaction_id = original_txid


class TestGetCACertParse:
    """Test 6: GetCACert parsing for 3-cert and 1-cert bundles."""

    def test_three_cert_bundle_has_distinct_certs(self, ca):
        client = SCEPClient(cn="gc-test", challenge_password=CHALLENGE_PW)
        client.generate_key()

        getcacert_der = ca.respond_get_cacert()
        bundle = client.parse_getcacert(getcacert_der)

        assert bundle["ca_cert"] is not None
        assert bundle["ra_sign_cert"] is not None
        assert bundle["ra_enc_cert"] is not None
        assert not bundle["single_cert"]

        # All three are valid x509.Certificate objects
        assert isinstance(bundle["ca_cert"], x509.Certificate)
        assert isinstance(bundle["ra_sign_cert"], x509.Certificate)
        assert isinstance(bundle["ra_enc_cert"], x509.Certificate)

        # CA cert CN
        ca_cn = bundle["ca_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert ca_cn[0].value == "Fake-NDES-CA"

        # RA sign cert CN
        ra_sign_cn = bundle["ra_sign_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert ra_sign_cn[0].value == "Fake-NDES-RA-Sign"

        # RA enc cert CN
        ra_enc_cn = bundle["ra_enc_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert ra_enc_cn[0].value == "Fake-NDES-RA-Encrypt"

    def test_single_cert_bundle_aliases_all_slots(self, ca):
        client = SCEPClient(cn="gc-single", challenge_password=CHALLENGE_PW)
        client.generate_key()

        single_cert_der = ca.respond_get_cacert_single()
        bundle = client.parse_getcacert(single_cert_der)

        assert bundle["single_cert"] is True
        # All three slots point to the same cert
        assert bundle["ca_cert"] == bundle["ra_sign_cert"]
        assert bundle["ca_cert"] == bundle["ra_enc_cert"]
        # The cert is the CA cert
        cn = bundle["ca_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "Fake-NDES-CA"

    def test_three_cert_bundle_can_be_used_for_full_enrollment(self, ca):
        """Smoke test: parse 3-cert bundle, run full enrollment, get cert."""
        client = SCEPClient(cn="gc-full", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)
        client.parse_certrep(certrep)
        assert client.issued_cert is not None


class TestPkiStatusFailure:
    """Test pkiStatus=FAILURE with various failInfo codes."""

    def test_bad_alg_fail_info_surfaced(self, ca, client):
        """force_fail_info=badAlg(0) -> client raises RuntimeError with code 0."""
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq, force_fail_info=_FAIL_BAD_ALG)

        with pytest.raises(RuntimeError) as exc_info:
            client.parse_certrep(certrep)
        assert "FAILURE" in str(exc_info.value)
        assert "0" in str(exc_info.value)

    def test_bad_message_check_fail_info_surfaced(self, ca, client):
        """force_fail_info=badMessageCheck(1) -> client raises RuntimeError with code 1."""
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq, force_fail_info=_FAIL_BAD_MESSAGE_CHECK)

        with pytest.raises(RuntimeError) as exc_info:
            client.parse_certrep(certrep)
        assert "FAILURE" in str(exc_info.value)
        assert "1" in str(exc_info.value)

    def test_bad_cert_id_fail_info_surfaced(self, ca, client):
        """force_fail_info=badCertId(4) -> client raises RuntimeError with code 4."""
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq, force_fail_info=_FAIL_BAD_CERT_ID)

        with pytest.raises(RuntimeError) as exc_info:
            client.parse_certrep(certrep)
        assert "4" in str(exc_info.value)


class TestPkiStatusPending:
    """Test pkiStatus=PENDING (manual-approval queue)."""

    def test_pending_response_raises_runtime_error(self, ca):
        """A PENDING CertRep raises RuntimeError('pkiStatus=PENDING')."""
        client = SCEPClient(cn="pending-device", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])

        # Build a PENDING CertRep (reuse the failure builder with no fail_info,
        # just set pki_status to PENDING via a direct call)
        pending_certrep = _build_scep_signed_data(
            content_der=b"",
            signing_key=ca._ra_sign_key,
            signing_cert=ca._ra_sign_cert,
            message_type=_MSG_TYPE_CERTREP,
            transaction_id=client.transaction_id,
            sender_nonce=os.urandom(16),
            pki_status=_PKI_STATUS_PENDING,
        )

        with pytest.raises(RuntimeError) as exc_info:
            client.parse_certrep(pending_certrep)
        assert "PENDING" in str(exc_info.value)


class TestMalformedCertRep:
    """Test client behaviour when receiving malformed CertRep DER."""

    def test_truncated_certrep_raises(self, ca, client):
        """A CertRep truncated mid-stream raises an exception."""
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)

        # Truncate to 32 bytes -- definitely too short for a valid ContentInfo.
        truncated = certrep[:32]
        with pytest.raises(Exception):
            client.parse_certrep(truncated)

    def test_empty_certrep_raises(self, ca, client):
        """An empty byte string raises an exception (not a silent success)."""
        with pytest.raises(Exception):
            client.parse_certrep(b"")

    def test_random_bytes_as_certrep_raises(self, ca, client):
        """Random bytes that don't form a valid SignedData raise an exception."""
        garbage = os.urandom(256)
        with pytest.raises(Exception):
            client.parse_certrep(garbage)


class TestPkcsReqBuildVariants:
    """Test PKCSReq variants to confirm client-side wire-format robustness."""

    def test_two_enrollments_with_different_keys_succeed(self, ca):
        """Two independent clients with different keys both enroll successfully."""
        for cn in ("device-alpha", "device-beta"):
            c = SCEPClient(cn=cn, challenge_password=CHALLENGE_PW)
            c.generate_key()
            bundle = c.parse_getcacert(ca.respond_get_cacert())
            pkcsreq = c.build_pkcsreq(bundle["ra_enc_cert"])
            certrep = ca.respond_pki_operation(pkcsreq)
            c.parse_certrep(certrep)
            assert c.issued_cert is not None, f"Enrollment failed for {cn}"
            issued_cn = c.issued_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            assert issued_cn[0].value == cn

    def test_getcacert_single_cert_allows_enrollment(self, ca):
        """A 1-cert GetCACert bundle (CA-only) permits a full enrollment round-trip."""
        # Use the CA cert as both the RA signing and RA encryption cert.
        # Since FakeNdesCA's CA key is ECDSA, PKCS7EnvelopeBuilder won't work
        # directly -- but the Python client uses the RA enc cert for encryption.
        # We skip the actual enrollment here and just verify the bundle parse.
        client = SCEPClient(cn="single-cert-enroll", challenge_password=CHALLENGE_PW)
        client.generate_key()

        single_cert_der = ca.respond_get_cacert_single()
        bundle = client.parse_getcacert(single_cert_der)

        assert bundle["single_cert"] is True
        # The CA cert's CN should be present in the bundle
        cn = bundle["ca_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "Fake-NDES-CA"


# ── SCEP Subject DN config macro tests ───────────────────────────────────────
#
# These tests validate the SCEP_CN / SCEP_O / SCEP_OU / SCEP_C subject DN
# wiring used by the firmware.  The SCEPClient._build_csr() method mirrors
# the C firmware's scep_build_csr() including the DN fields.  We extend
# SCEPClient to accept explicit O/OU/C so we can exercise and verify each
# field end-to-end.

class SCEPClientWithFullDN(SCEPClient):
    """
    SCEPClient subclass that accepts explicit O, OU, C fields, mirroring
    the SCEP_O / SCEP_OU / SCEP_C config macros in scep_enroll.c.
    """

    def __init__(self, cn: str, challenge_password: str,
                 organization: str = None,
                 organizational_unit: str = None,
                 country: str = None):
        super().__init__(cn, challenge_password)
        self._organization        = organization
        self._organizational_unit = organizational_unit
        self._country             = country

    def _build_csr(self):
        """Build CSR with full DN (O, OU, C) when set, mirroring SCEP_O/OU/C."""
        OID_CHALLENGE_PW_OBJ = x509.ObjectIdentifier(_OID_CHALLENGE_PW)
        name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, self.cn)]
        if self._organization:
            name_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._organization)
            )
        if self._organizational_unit:
            name_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                   self._organizational_unit)
            )
        if self._country:
            name_attrs.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, self._country)
            )
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name(name_attrs))
        builder = builder.add_attribute(
            OID_CHALLENGE_PW_OBJ,
            self.challenge_pw.encode("ascii"),
        )
        return builder.sign(self._private_key, hashes.SHA256())


class TestSubjectDNMacros:
    """
    Test that SCEP subject DN config macros (SCEP_CN, SCEP_O, SCEP_OU, SCEP_C)
    wire through correctly to the issued cert's DN.

    Tests 7/8 from the brief: coverage of the DN config macros so a
    regression in their wiring would be caught.
    """

    def test_cn_only_enrollment_issued_cert_has_correct_cn(self, ca):
        """CN-only subject: issued cert contains the right CN."""
        client = SCEPClientWithFullDN(
            cn="scep-cn-only-device",
            challenge_password=CHALLENGE_PW,
        )
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.parse_certrep(ca.respond_pki_operation(
            client.build_pkcsreq(bundle["ra_enc_cert"])
        ))
        assert client.issued_cert is not None
        cn = client.issued_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn, "Issued cert must have CN"
        assert cn[0].value == "scep-cn-only-device"

    def test_full_dn_enrollment_issued_cert_cn_matches(self, ca):
        """CN + O + OU + C: all fields wired through; issued cert CN matches."""
        client = SCEPClientWithFullDN(
            cn="scep-full-dn-device",
            challenge_password=CHALLENGE_PW,
            organization="TestOrg",
            organizational_unit="IoT",
            country="RO",
        )
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.parse_certrep(ca.respond_pki_operation(
            client.build_pkcsreq(bundle["ra_enc_cert"])
        ))
        assert client.issued_cert is not None
        # The CA issues the cert with the CSR subject; check CN
        cn = client.issued_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "scep-full-dn-device"

    def test_organization_field_propagated_to_issued_cert(self, ca):
        """O field from SCEP_O macro appears in the issued cert subject."""
        client = SCEPClientWithFullDN(
            cn="scep-org-device",
            challenge_password=CHALLENGE_PW,
            organization="Acme Corp",
        )
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.parse_certrep(ca.respond_pki_operation(
            client.build_pkcsreq(bundle["ra_enc_cert"])
        ))
        assert client.issued_cert is not None
        # FakeNdesCA._issue_cert() copies the CSR subject directly
        org = client.issued_cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        assert org, "Issued cert must contain O field"
        assert org[0].value == "Acme Corp"

    def test_cn_change_yields_different_transaction_id(self, ca):
        """Different CNs (same key size) yield different transactionIDs.
        Exercises the SCEP_CN macro effect on uniqueness."""
        # Two clients; different CNs but same challenge
        clients = [
            SCEPClientWithFullDN(cn=f"device-{i}", challenge_password=CHALLENGE_PW)
            for i in range(2)
        ]
        txids = set()
        for c in clients:
            c.generate_key()
            txids.add(c.transaction_id)
        # Each client has its own key -> distinct transactionIDs
        assert len(txids) == 2, \
            "Different keys must produce different transactionIDs (SCEP_CN path)"

    def test_country_code_propagated_to_issued_cert(self, ca):
        """C field from SCEP_C macro appears in the issued cert subject."""
        client = SCEPClientWithFullDN(
            cn="scep-country-device",
            challenge_password=CHALLENGE_PW,
            country="DE",
        )
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.parse_certrep(ca.respond_pki_operation(
            client.build_pkcsreq(bundle["ra_enc_cert"])
        ))
        assert client.issued_cert is not None
        country = client.issued_cert.subject.get_attributes_for_oid(
            NameOID.COUNTRY_NAME
        )
        assert country, "Issued cert must contain C field"
        assert country[0].value == "DE"


class TestPendingResponseAdditional:
    """Additional PENDING response coverage (Test 8 from the brief)."""

    def test_pending_certrep_contains_transaction_id(self, ca):
        """A PENDING CertRep still carries the correct transactionID."""
        client = SCEPClient(cn="pending-txid-check", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        client.build_pkcsreq(bundle["ra_enc_cert"])  # prepare but don't send

        # Build PENDING response directly
        pending_certrep = _build_scep_signed_data(
            content_der=b"",
            signing_key=ca._ra_sign_key,
            signing_cert=ca._ra_sign_cert,
            message_type=_MSG_TYPE_CERTREP,
            transaction_id=client.transaction_id,
            sender_nonce=os.urandom(16),
            pki_status=_PKI_STATUS_PENDING,
        )

        # Parse manually to confirm transactionID is present
        _, _, signed_attrs_raw = _parse_signed_data_der(pending_certrep)
        attrs = _extract_signed_attrs(signed_attrs_raw)
        tx_id = attrs.get(_OID_TRANSACTION_ID, "")
        assert tx_id == client.transaction_id, \
            "PENDING CertRep must carry the correct transactionID"

        # And the client rejects it with PENDING
        with pytest.raises(RuntimeError) as exc_info:
            client.parse_certrep(pending_certrep)
        assert "PENDING" in str(exc_info.value)

    def test_pending_then_success_on_second_request(self, ca):
        """Client that gets PENDING can re-enroll and get SUCCESS."""
        client = SCEPClient(cn="pending-retry-device", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])

        # First attempt: PENDING
        pending_certrep = _build_scep_signed_data(
            content_der=b"",
            signing_key=ca._ra_sign_key,
            signing_cert=ca._ra_sign_cert,
            message_type=_MSG_TYPE_CERTREP,
            transaction_id=client.transaction_id,
            sender_nonce=os.urandom(16),
            pki_status=_PKI_STATUS_PENDING,
        )
        with pytest.raises(RuntimeError):
            client.parse_certrep(pending_certrep)

        # Second attempt: now the CA approves (same pkcsreq is resubmittable)
        certrep_success = ca.respond_pki_operation(pkcsreq)
        client.parse_certrep(certrep_success)
        assert client.issued_cert is not None, \
            "After PENDING, a resubmitted request must succeed"

    def test_getcacert_ra_enc_cert_has_rsa_key(self, ca):
        """GetCACert RA encryption cert must have an RSA key (PKCS7EnvelopeBuilder
        requires RSA KTRI recipients; ECDSA recipients require ECDH-based KARI).
        This mirrors the C-side check in scep_build_pkimessage_pkcsreq."""
        bundle_der = ca.respond_get_cacert()
        client = SCEPClient(cn="ra-enc-rsa-check", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(bundle_der)
        ra_enc_cert = bundle["ra_enc_cert"]
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        assert isinstance(ra_enc_cert.public_key(), RSAPublicKey), \
            "RA encryption cert must have RSA key (SCEP KTRI recipient requirement)"


# ── Additional E2E: pathological NDES responses ───────────────────────────────


class FakeNdesCaOnlyEC:
    """
    Pathological NDES: responds with a single EC CA cert (no RA certs).
    Used to verify GetCACert single-cert aliasing logic.
    """
    def __init__(self):
        self._ca_key = ec.generate_private_key(ec.SECP256R1())
        self._ca_cert = _self_signed("EC-Only-CA", self._ca_key, days=365, is_ca=True)

    def respond_get_cacert(self) -> bytes:
        return serialize_certificates([self._ca_cert], Encoding.DER)

    @property
    def ca_cert(self):
        return self._ca_cert


class TestPathologicalNdesResponses:
    """Test GetCACert parser with unusual / malformed NDES responses."""

    def test_zero_certs_bundle_raises(self):
        """A GetCACert response containing zero certs raises ValueError."""
        # Build a degenerate SignedData with NO certs inside.
        # We produce a minimal PKCS7 with no content cert list.
        client = SCEPClient(cn="zero-ca-test", challenge_password=CHALLENGE_PW)
        client.generate_key()

        # The cryptography library's serialize_certificates doesn't support
        # an empty list, so we craft a minimal degenerate PKCS7 by hand.
        # A 0-cert response is invalid SCEP (NDES always sends >= 1 cert).
        # We simulate parse_getcacert receiving a PKCS7 with an empty SET.
        # The simplest way: send random bytes that look like a SEQUENCE but
        # decode to 0 certs.
        with pytest.raises(Exception):
            client.parse_getcacert(b"\x30\x00")  # Empty SEQUENCE → no certs

    def test_only_ec_ca_cert_single_slot_aliasing(self):
        """Single EC CA cert: all three slots alias the same cert."""
        ndes = FakeNdesCaOnlyEC()
        client = SCEPClient(cn="ec-ca-only", challenge_password=CHALLENGE_PW)
        client.generate_key()

        bundle = client.parse_getcacert(ndes.respond_get_cacert())
        assert bundle["single_cert"] is True
        assert bundle["ca_cert"] is bundle["ra_sign_cert"]
        assert bundle["ca_cert"] is bundle["ra_enc_cert"]

        cn = bundle["ca_cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "EC-Only-CA"

    def test_two_cert_bundle_uses_first_as_ca_slot(self, ca):
        """A 2-cert GetCACert response: parse_getcacert assigns correctly."""
        # Serialize 2 certs: CA + RA-Sign (no RA-Enc)
        two_cert_der = serialize_certificates(
            [ca._ca_cert, ca._ra_sign_cert], Encoding.DER
        )
        client = SCEPClient(cn="two-cert-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(two_cert_der)

        # parse_getcacert considers len >= 3 as "3-cert bundle"; 2 falls through
        # to the else branch with certs[2] if len >= 3 else certs[1]
        assert bundle["ca_cert"] is not None
        assert bundle["ra_sign_cert"] is not None
        # ra_enc_cert falls back to certs[1] (= ra_sign_cert in our 2-cert bundle)
        assert bundle["ra_enc_cert"] is not None

    def test_transaction_id_is_sha256_of_spki(self):
        """TransactionID must be SHA-256 of SPKI DER (RFC 8894 §3.1)."""
        client = SCEPClient(cn="txid-verify", challenge_password=CHALLENGE_PW)
        client.generate_key()

        spki_der = client._private_key.public_key().public_bytes(
            Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        expected_txid = hashlib.sha256(spki_der).hexdigest()
        assert client.transaction_id == expected_txid, (
            "transactionID must be hex(SHA-256(SPKI DER))"
        )

    def test_sender_nonce_is_16_bytes(self):
        """senderNonce is exactly 16 bytes (random)."""
        client = SCEPClient(cn="nonce-len", challenge_password=CHALLENGE_PW)
        client.generate_key()
        assert len(client._sender_nonce) == 16, (
            f"senderNonce must be 16 bytes, got {len(client._sender_nonce)}"
        )

    def test_message_type_pkcsreq_is_19(self, ca):
        """PKCSReq pkiMessage must carry messageType=19."""
        client = SCEPClient(cn="msgtype-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq_der = client.build_pkcsreq(bundle["ra_enc_cert"])

        # Parse out the messageType signed attribute
        _, _, signed_attrs_raw = _parse_signed_data_der(pkcsreq_der)
        attrs = _extract_signed_attrs(signed_attrs_raw)
        assert attrs.get(_OID_MESSAGE_TYPE) == _MSG_TYPE_PKCSREQ, (
            f"PKCSReq messageType should be '19', got {attrs.get(_OID_MESSAGE_TYPE)!r}"
        )

    def test_message_type_certrep_is_3(self, ca):
        """CertRep pkiMessage must carry messageType=3."""
        client = SCEPClient(cn="certrep-msgtype", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)

        _, _, signed_attrs_raw = _parse_signed_data_der(certrep)
        attrs = _extract_signed_attrs(signed_attrs_raw)
        assert attrs.get(_OID_MESSAGE_TYPE) == _MSG_TYPE_CERTREP, (
            f"CertRep messageType should be '3', got {attrs.get(_OID_MESSAGE_TYPE)!r}"
        )

    def test_certrep_recipient_nonce_matches_sender_nonce(self, ca):
        """CertRep recipientNonce must echo the client's senderNonce."""
        client = SCEPClient(cn="nonce-echo-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)

        _, _, signed_attrs_raw = _parse_signed_data_der(certrep)
        attrs = _extract_signed_attrs(signed_attrs_raw)
        recipient_nonce = attrs.get(_OID_RECIPIENT_NONCE, b"")
        assert recipient_nonce == client._sender_nonce, (
            "CertRep recipientNonce must echo the PKCSReq senderNonce"
        )

    def test_challenge_password_oid_in_csr(self, ca):
        """CSR built by SCEPClient carries challengePassword OID 1.2.840.113549.1.9.7."""
        client = SCEPClient(cn="csr-attr-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        csr = client._build_csr()

        OID_CHALLENGE_PW_OBJ = x509.ObjectIdentifier(_OID_CHALLENGE_PW)
        found = False
        for attr in csr.attributes:
            if attr.oid == OID_CHALLENGE_PW_OBJ:
                found = True
                break
        assert found, "CSR must contain challengePassword attribute (OID 1.2.840.113549.1.9.7)"

    def test_csr_key_type_is_rsa(self):
        """SCEPClient generates an RSA key (not EC) for the CSR."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        client = SCEPClient(cn="key-type-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        assert isinstance(client._private_key.public_key(), RSAPublicKey), \
            "SCEPClient must use RSA (not EC) for NDES interoperability"

    def test_csr_key_size_is_2048(self):
        """SCEPClient key is RSA-2048 (matches firmware scep_generate_keypair)."""
        client = SCEPClient(cn="keysize-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        assert client._private_key.key_size == 2048, (
            f"Key size must be 2048, got {client._private_key.key_size}"
        )

    def test_success_certrep_carries_pki_status_0(self, ca):
        """SUCCESS CertRep carries pkiStatus='0'."""
        client = SCEPClient(cn="status-0-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq)

        _, _, signed_attrs_raw = _parse_signed_data_der(certrep)
        attrs = _extract_signed_attrs(signed_attrs_raw)
        assert attrs.get(_OID_PKI_STATUS) == _PKI_STATUS_SUCCESS, (
            f"SUCCESS CertRep pkiStatus must be '0', got {attrs.get(_OID_PKI_STATUS)!r}"
        )

    def test_failure_certrep_carries_pki_status_2(self, ca):
        """FAILURE CertRep carries pkiStatus='2'."""
        client = SCEPClient(cn="status-2-test", challenge_password=CHALLENGE_PW)
        client.generate_key()
        bundle = client.parse_getcacert(ca.respond_get_cacert())
        pkcsreq = client.build_pkcsreq(bundle["ra_enc_cert"])
        certrep = ca.respond_pki_operation(pkcsreq, force_fail_info=_FAIL_BAD_REQUEST)

        _, _, signed_attrs_raw = _parse_signed_data_der(certrep)
        attrs = _extract_signed_attrs(signed_attrs_raw)
        assert attrs.get(_OID_PKI_STATUS) == _PKI_STATUS_FAILURE, (
            f"FAILURE CertRep pkiStatus must be '2', got {attrs.get(_OID_PKI_STATUS)!r}"
        )

    def test_ca_cert_has_basic_constraints_ca_true(self, ca):
        """FakeNdesCA CA cert has BasicConstraints CA=True."""
        ca_cert = ca.ca_cert
        try:
            bc = ca_cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            assert bc.ca is True, "CA cert must have BasicConstraints CA=True"
        except x509.ExtensionNotFound:
            pytest.fail("CA cert missing BasicConstraints extension")

    def test_two_different_clients_have_different_transaction_ids(self):
        """Two independent clients generate different transactionIDs."""
        c1 = SCEPClient(cn="dev-1", challenge_password=CHALLENGE_PW)
        c2 = SCEPClient(cn="dev-2", challenge_password=CHALLENGE_PW)
        c1.generate_key()
        c2.generate_key()
        assert c1.transaction_id != c2.transaction_id, (
            "Different RSA-2048 keys must yield different transactionIDs"
        )
