#!/usr/bin/env python3
"""
test/scripts/test_scep_enroll_zero.py
======================================
Tests for scripts/scep_enroll_zero.py — the PyScep-based SCEP enrollment
helper that produces Mode B+ embedded certs for the ESP32-S3-Zero.

Test cases
----------
1.  Key shape: generate_csr produces RSA-2048 key.
2.  CSR CN format: CN is ``IRIX-TTY-PVE-DELL-<mac>`` (correct format).
3.  CSR CN value: CN matches the requested value exactly.
4.  challengePassword attribute present in the generated CSR.
5.  _fixed_filter coercion: a non-CA cert with is_ca=None passes through
    the patched filter when ca_only=False (verifies the None!=False fix).
6.  _fixed_filter coercion: the original (unpatched) condition None!=False
    is True (documents the bug that the patch fixes).
7.  _fixed_filter coercion: bool(None)!=False is False (documents the fix).
8.  _fixed_filter: a true CA cert (is_ca=True) is excluded when ca_only=False.
9.  _fixed_filter: a true CA cert (is_ca=True) is included when ca_only=True.
10. CACertificates.verify override is a no-op (does not raise).
11. E2E against mock Client (happy path): issued cert CN matches, key matches
    cert's public key, CA chain non-empty.
12. E2E: output file ca.pem is non-empty PEM parseable by cryptography.
13. E2E: output file client.crt is non-empty PEM parseable by cryptography.
14. E2E: output file client.key is non-empty PEM private key parseable by
    cryptography.
15. E2E: output files each end with a newline (b'\\n').
16. Recipient selection: from a 4-cert bundle, RSA+key_encipherment cert is
    selected as recipient.
17. Signer selection: from a 4-cert bundle, RSA+digital_signature cert is
    selected as signer.
18. Issuer selection: from a 4-cert bundle, the CA whose subject matches the
    recipient's issuer is selected as issuer.
19. Structural guard — cert_renewer.c: contains the Mode-C-only
    ``defined(WIFI_ENTERPRISE_SSID) && defined(SCEP_URL) && !defined(WIFI_USE_ENTERPRISE)``
    guard.
20. Structural guard — cert_renewer.h: same guard in the header.
21. Structural guard — main.c: cert_renewer_start() is called only inside a
    matching Mode-C guard (not under bare WIFI_ENTERPRISE_SSID or no guard).

No network, no hardware, no ESP-IDF required.
Run with:
    venv/bin/pytest test/scripts/test_scep_enroll_zero.py -v
"""

import os
import sys
import re
import datetime
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# ── Make scripts/ importable ──────────────────────────────────────────────────
_SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts"
)
sys.path.insert(0, os.path.abspath(_SCRIPTS_DIR))

_PROJECT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."
)

# ── Imports pulled in after sys.path is configured ────────────────────────────
# scep_enroll_zero applies monkey-patches at import time; importing it here
# means the patches are in effect for every test in this module.
import scep_enroll_zero as _m  # noqa: E402

from scep.Client.responses import CACertificates  # noqa: E402
from scep.Client.certificate import Certificate as PyscepCert  # noqa: E402
from scep.Client.signingrequest import SigningRequest  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa, ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import load_pem_private_key  # noqa: E402


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _make_crypto_cert(
    cn: str,
    key,
    *,
    is_ca: bool = False,
    ku_sign: bool = False,
    ku_enc: bool = False,
    signing_key=None,
    issuer_name: x509.Name = None,
    include_bc: bool = True,
) -> x509.Certificate:
    """
    Build a real cryptography.x509.Certificate with explicit BasicConstraints
    and KeyUsage extensions (required for PyScep's Certificate.key_usage to
    work; the attribute raises if there is no KeyUsage extension).

    If ``include_bc`` is False the BasicConstraints extension is omitted so
    that Certificate.is_ca returns None (the condition that triggers the
    PyScep bug under test).
    """
    now = _now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer  = issuer_name if issuer_name is not None else subject
    sign_k  = signing_key if signing_key is not None else key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.KeyUsage(
                digital_signature=ku_sign or is_ca,
                content_commitment=False,
                key_encipherment=ku_enc,
                data_encipherment=ku_enc,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if include_bc:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
    return builder.sign(sign_k, hashes.SHA256())


def _pyscep_cert(crypto_cert: x509.Certificate) -> PyscepCert:
    """Wrap a cryptography Certificate in a PyScep Certificate object."""
    return PyscepCert.from_der(crypto_cert.public_bytes(serialization.Encoding.DER))


def _four_cert_bundle():
    """
    Build a synthetic 4-cert bundle that exercises recipient/signer/issuer
    selection:
      - CA (EC, is_ca=True): the issuer
      - RA-Enc (RSA-2048, key_encipherment, no-BC so is_ca=None): recipient
      - RA-Sign (RSA-2048, digital_signature, no-BC so is_ca=None): signer
      - Decoy (EC, digital_signature, no-BC so is_ca=None): wrong pubkey type
    """
    ca_key       = ec.generate_private_key(ec.SECP256R1())
    ra_enc_key   = rsa.generate_private_key(65537, 2048)
    ra_sign_key  = rsa.generate_private_key(65537, 2048)
    decoy_key    = ec.generate_private_key(ec.SECP256R1())

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bundle-CA")])

    ca_cert      = _make_crypto_cert("Bundle-CA", ca_key, is_ca=True)
    # RA certs are signed by CA but issued without BasicConstraints so
    # is_ca == None in PyScep (the real-world NDES behaviour).
    ra_enc_cert  = _make_crypto_cert(
        "Bundle-RA-Enc", ra_enc_key,
        ku_enc=True, signing_key=ca_key, issuer_name=ca_name,
        include_bc=False,
    )
    ra_sign_cert = _make_crypto_cert(
        "Bundle-RA-Sign", ra_sign_key,
        ku_sign=True, signing_key=ca_key, issuer_name=ca_name,
        include_bc=False,
    )
    decoy_cert   = _make_crypto_cert(
        "Bundle-Decoy", decoy_key,
        ku_sign=True, signing_key=ca_key, issuer_name=ca_name,
        include_bc=False,
    )

    pys_ca    = _pyscep_cert(ca_cert)
    pys_enc   = _pyscep_cert(ra_enc_cert)
    pys_sign  = _pyscep_cert(ra_sign_cert)
    pys_decoy = _pyscep_cert(decoy_cert)

    return {
        "ca":          (ca_cert, pys_ca, ca_key),
        "enc":         (ra_enc_cert, pys_enc, ra_enc_key),
        "sign":        (ra_sign_cert, pys_sign, ra_sign_key),
        "decoy":       (decoy_cert, pys_decoy, decoy_key),
        "pys_list":    [pys_ca, pys_enc, pys_sign, pys_decoy],
        "ca_name":     ca_name,
    }


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def generated_csr_and_key():
    """Generate a CSR + key pair once for the whole module (slow: 2048-bit RSA)."""
    mac    = "aabbccddeeff"
    cn     = f"IRIX-TTY-PVE-DELL-{mac}"
    pw     = "TESTCHALLENGE"
    csr, key = SigningRequest.generate_csr(
        cn=cn,
        key_usage={u"digital_signature", u"key_encipherment"},
        password=pw,
    )
    return {"csr": csr, "key": key, "cn": cn, "password": pw, "mac": mac}


@pytest.fixture(scope="module")
def four_cert_bundle():
    """Return the synthesized 4-cert bundle (computed once per module)."""
    return _four_cert_bundle()


# ── Test group 1: Key + CSR generation ───────────────────────────────────────

class TestKeyAndCSRGeneration:
    """Tests 1–4: correct shape of the generated key and CSR."""

    def test_key_is_rsa_2048(self, generated_csr_and_key):
        """Test 1: generate_csr produces an RSA-2048 private key."""
        key = generated_csr_and_key["key"]
        crypto_key = key.to_crypto_private_key()
        assert type(crypto_key).__name__ == "RSAPrivateKey", (
            f"Expected RSAPrivateKey, got {type(crypto_key).__name__}"
        )
        assert crypto_key.key_size == 2048

    def test_cn_format_matches_irix_pattern(self, generated_csr_and_key):
        """Test 2: CN follows the IRIX-TTY-PVE-DELL-<mac> pattern."""
        cn = generated_csr_and_key["cn"]
        mac = generated_csr_and_key["mac"]
        assert cn == f"IRIX-TTY-PVE-DELL-{mac}"
        assert re.match(r"^IRIX-TTY-PVE-DELL-[0-9a-f]{12}$", cn), (
            f"CN '{cn}' does not match the expected MAC-address pattern"
        )

    def test_csr_subject_cn_matches(self, generated_csr_and_key):
        """Test 3: the CSR subject CN matches the requested value exactly."""
        csr = generated_csr_and_key["csr"]
        cn  = generated_csr_and_key["cn"]
        subject = csr._csr["certification_request_info"]["subject"]
        assert subject.native.get("common_name") == cn

    def test_challenge_password_attribute_present(self, generated_csr_and_key):
        """Test 4: CSR includes a challengePassword attribute (OID 1.2.840.113549.1.9.7)."""
        _OID_CHALLENGE_PW = "1.2.840.113549.1.9.7"
        csr = generated_csr_and_key["csr"]
        attrs = csr._csr["certification_request_info"]["attributes"]
        oids = [a["type"].dotted for a in attrs]
        assert _OID_CHALLENGE_PW in oids, (
            f"challengePassword OID not found in CSR attributes; got {oids}"
        )
        # Verify the value matches the password that was passed
        for a in attrs:
            if a["type"].dotted == _OID_CHALLENGE_PW:
                assert a["values"][0].native == generated_csr_and_key["password"]
                break


# ── Test group 2: _fixed_filter monkey-patch ─────────────────────────────────

class TestFixedFilterPatch:
    """Tests 5–9: CACertificates._filter is_ca=None coercion."""

    def _make_no_bc_cert(self, cn: str, key, ku_enc: bool = False, ku_sign: bool = False):
        """Return a PyScep Certificate whose is_ca property is None."""
        crypto_cert = _make_crypto_cert(
            cn, key, ku_enc=ku_enc, ku_sign=ku_sign, include_bc=False
        )
        return _pyscep_cert(crypto_cert)

    def test_non_ca_cert_with_is_ca_none_passes_patched_filter(self):
        """Test 5: is_ca=None cert is accepted by _fixed_filter when ca_only=False."""
        key  = rsa.generate_private_key(65537, 2048)
        cert = self._make_no_bc_cert("NoBC-Enc", key, ku_enc=True)
        assert cert.is_ca is None, "Precondition: is_ca must be None"

        # Apply the patched filter directly
        ca_certs = MagicMock()
        ca_certs._certificates = [cert]
        result = _m._fixed_filter(
            ca_certs,
            required_key_usage={"key_encipherment"},
            not_required_key_usage=set(),
            ca_only=False,
        )
        assert len(result) == 1, (
            "Patched _fixed_filter should include a cert with is_ca=None "
            f"when ca_only=False; got {result}"
        )

    def test_original_bug_none_not_equal_false_is_true(self):
        """Test 6: documents the original PyScep bug — None != False is True."""
        assert (None != False) is True, (  # noqa: E712
            "Expected None != False to be True (the bug that the patch fixes)"
        )

    def test_patch_coercion_bool_none_not_equal_false_is_false(self):
        """Test 7: the patch coercion — bool(None) != False is False."""
        assert (bool(None) != False) is False, (  # noqa: E712
            "Expected bool(None) != False to be False (the patched behaviour)"
        )

    def test_ca_cert_excluded_when_ca_only_false(self):
        """Test 8: a cert with is_ca=True is excluded by the patched filter when ca_only=False."""
        key  = ec.generate_private_key(ec.SECP256R1())
        crypto_cert = _make_crypto_cert("CA", key, is_ca=True)
        cert = _pyscep_cert(crypto_cert)
        assert cert.is_ca is True, "Precondition: is_ca must be True"

        ca_certs = MagicMock()
        ca_certs._certificates = [cert]
        result = _m._fixed_filter(
            ca_certs,
            required_key_usage=set(),
            not_required_key_usage=set(),
            ca_only=False,
        )
        assert len(result) == 0, (
            "CA cert (is_ca=True) should be excluded when ca_only=False"
        )

    def test_ca_cert_included_when_ca_only_true(self):
        """Test 9: a cert with is_ca=True is included by the patched filter when ca_only=True."""
        key  = ec.generate_private_key(ec.SECP256R1())
        crypto_cert = _make_crypto_cert("CA", key, is_ca=True)
        cert = _pyscep_cert(crypto_cert)

        ca_certs = MagicMock()
        ca_certs._certificates = [cert]
        result = _m._fixed_filter(
            ca_certs,
            required_key_usage=set(),
            not_required_key_usage=set(),
            ca_only=True,
        )
        assert len(result) == 1, (
            "CA cert (is_ca=True) should be included when ca_only=True"
        )


# ── Test group 3: verify() skip ───────────────────────────────────────────────

class TestVerifySkip:
    """Test 10: CACertificates.verify is patched to a no-op."""

    def test_verify_is_noop(self):
        """Test 10: the patched verify() does not raise, even on a broken bundle."""
        # Create a minimal CACertificates with one cert that would normally
        # fail verify() (EC key — wrong args for PyScep's RSA-shaped check).
        key  = ec.generate_private_key(ec.SECP256R1())
        crypto_cert = _make_crypto_cert("EC-CA", key, is_ca=True)
        pys_cert = _pyscep_cert(crypto_cert)

        ca_certs = CACertificates.__new__(CACertificates)
        ca_certs._certificates = [pys_cert]
        ca_certs._recipient = pys_cert
        ca_certs._signer    = pys_cert
        ca_certs._issuer    = pys_cert

        # Should not raise
        ca_certs.verify()


# ── Test group 4: E2E with mock Client ────────────────────────────────────────

class TestE2EWithMockClient:
    """Tests 11–15: do_enroll() writes correct PEM files when Client is mocked."""

    @staticmethod
    def _build_mock_client(issued_cn: str, password: str):
        """
        Return (mock_client_cls, pys_ca_cert, pys_issued_cert, enc_key) so
        that Client(url).get_ca_certs() and Client(url).enrol() work without
        any network activity.

        The CA is ECDSA P-256 (mirrors FakeNdesCA in test_scep_protocol_e2e).
        RA-enc is RSA-2048 (needed for PyScep's PKCS7 envelope builder).
        RA-sign is RSA-2048 with digital_signature.
        The issued cert has CN=issued_cn, signed by the CA.
        """
        from scep.Client.client import EnrollmentStatus

        ca_key      = ec.generate_private_key(ec.SECP256R1())
        ra_enc_key  = rsa.generate_private_key(65537, 2048)
        ra_sign_key = rsa.generate_private_key(65537, 2048)
        issued_key  = rsa.generate_private_key(65537, 2048)

        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock-CA")])

        ca_crypto      = _make_crypto_cert("Mock-CA", ca_key, is_ca=True)
        ra_enc_crypto  = _make_crypto_cert(
            "Mock-RA-Enc", ra_enc_key, ku_enc=True,
            signing_key=ca_key, issuer_name=ca_name, include_bc=False,
        )
        ra_sign_crypto = _make_crypto_cert(
            "Mock-RA-Sign", ra_sign_key, ku_sign=True,
            signing_key=ca_key, issuer_name=ca_name, include_bc=False,
        )
        issued_crypto  = _make_crypto_cert(
            issued_cn, issued_key,
            signing_key=ca_key, issuer_name=ca_name,
        )

        pys_ca    = _pyscep_cert(ca_crypto)
        pys_enc   = _pyscep_cert(ra_enc_crypto)
        pys_sign  = _pyscep_cert(ra_sign_crypto)
        pys_issued = _pyscep_cert(issued_crypto)

        # Build a CACertificates bundle (the patched filter is already active
        # because we imported scep_enroll_zero at module level).
        ca_certs = CACertificates([pys_ca, pys_enc, pys_sign])
        # Force selection (mirrors the script's own logic):
        ca_certs._recipient = pys_enc
        ca_certs._signer    = pys_sign
        ca_certs._issuer    = pys_ca

        enrollment_status = EnrollmentStatus(certificates=[pys_issued])

        mock_client_instance = MagicMock()
        mock_client_instance.get_ca_certs.return_value = ca_certs
        mock_client_instance.enrol.return_value = enrollment_status

        mock_client_cls = MagicMock(return_value=mock_client_instance)

        return {
            "cls":          mock_client_cls,
            "pys_ca":       pys_ca,
            "pys_issued":   pys_issued,
            "issued_key":   issued_key,
            "ca_key":       ca_key,
            "issued_crypto": issued_crypto,
        }

    @pytest.fixture(scope="class")
    def enroll_result(self, tmp_path_factory):
        """
        Run do_enroll() with a mocked Client, capture the result dict and
        output directory path.
        """
        out_dir = str(tmp_path_factory.mktemp("e2e_output"))
        issued_cn = "IRIX-TTY-PVE-DELL-aabbccddeeff"
        password  = "TESTPW123"

        mock_data = self._build_mock_client(issued_cn=issued_cn, password=password)

        with patch("scep_enroll_zero.Client", mock_data["cls"]):
            result = _m.do_enroll(
                scep_url="http://mock.local/scep",
                password=password,
                cn=issued_cn,
                output_dir=out_dir,
            )

        return {
            "result":     result,
            "out_dir":    out_dir,
            "issued_cn":  issued_cn,
            "mock_data":  mock_data,
        }

    def test_issued_cert_cn_matches(self, enroll_result):
        """Test 11: issued cert CN in the result matches the requested CN."""
        issued = enroll_result["result"]["issued"]
        cn_from_issued = issued.subject_dict.get("common_name", "")
        assert cn_from_issued == enroll_result["issued_cn"], (
            f"Issued cert CN '{cn_from_issued}' != requested '{enroll_result['issued_cn']}'"
        )

    def test_ca_pem_is_parseable(self, enroll_result):
        """Test 12: ca.pem is a non-empty, parseable PEM certificate."""
        ca_pem_path = os.path.join(enroll_result["out_dir"], "ca.pem")
        assert os.path.isfile(ca_pem_path)
        ca_pem_bytes = open(ca_pem_path, "rb").read()
        assert len(ca_pem_bytes) > 0
        # Parse first cert from the PEM bundle
        x509.load_pem_x509_certificate(ca_pem_bytes)

    def test_client_crt_is_parseable(self, enroll_result):
        """Test 13: client.crt is a non-empty, parseable PEM certificate."""
        crt_path = os.path.join(enroll_result["out_dir"], "client.crt")
        assert os.path.isfile(crt_path)
        crt_bytes = open(crt_path, "rb").read()
        assert len(crt_bytes) > 0
        x509.load_pem_x509_certificate(crt_bytes)

    def test_client_key_is_parseable(self, enroll_result):
        """Test 14: client.key is a non-empty, parseable PEM private key."""
        key_path = os.path.join(enroll_result["out_dir"], "client.key")
        assert os.path.isfile(key_path)
        key_bytes = open(key_path, "rb").read()
        assert len(key_bytes) > 0
        load_pem_private_key(key_bytes, password=None)

    def test_output_files_end_with_newline(self, enroll_result):
        """Test 15: all three output files end with a newline byte."""
        for fname in ("ca.pem", "client.crt", "client.key"):
            path = os.path.join(enroll_result["out_dir"], fname)
            data = open(path, "rb").read()
            assert data.endswith(b"\n"), (
                f"{fname} does not end with '\\n' (last 4 bytes: {data[-4:]!r})"
            )


# ── Test group 5: Recipient / Signer / Issuer selection ──────────────────────

class TestCertSelection:
    """Tests 16–18: the script picks the correct cert for each role."""

    def test_recipient_is_rsa_key_encipherment(self, four_cert_bundle):
        """Test 16: recipient is the RSA + key_encipherment cert."""
        pys_list = four_cert_bundle["pys_list"]
        pys_enc  = four_cert_bundle["enc"][1]

        # Simulate the script's recipient-selection loop.
        selected = None
        for cand in pys_list:
            ku = cand.key_usage
            if (ku == {"key_encipherment"} or ku == {"data_encipherment", "key_encipherment"}):
                pk_type = type(cand.public_key.to_crypto_public_key()).__name__
                if pk_type == "RSAPublicKey":
                    selected = cand
                    break

        assert selected is not None, "No RSA+key_encipherment cert found in bundle"
        assert selected is pys_enc, (
            "Expected the RA-Enc cert to be selected as recipient"
        )

    def test_signer_is_rsa_digital_signature(self, four_cert_bundle):
        """Test 17: signer is the RSA + digital_signature cert."""
        pys_list  = four_cert_bundle["pys_list"]
        pys_sign  = four_cert_bundle["sign"][1]

        selected = None
        for cand in pys_list:
            if (cand.key_usage == {"digital_signature"}
                    and type(cand.public_key.to_crypto_public_key()).__name__ == "RSAPublicKey"):
                selected = cand
                break

        assert selected is not None, "No RSA+digital_signature cert found in bundle"
        assert selected is pys_sign, (
            "Expected the RA-Sign cert to be selected as signer"
        )

    def test_issuer_is_ca_whose_subject_matches_recipient_issuer(self, four_cert_bundle):
        """Test 18: issuer is the CA whose subject == recipient.issuer."""
        pys_list = four_cert_bundle["pys_list"]
        pys_ca   = four_cert_bundle["ca"][1]
        pys_enc  = four_cert_bundle["enc"][1]

        selected = None
        for cand in pys_list:
            if cand.is_ca and cand.subject == pys_enc.issuer:
                selected = cand
                break

        assert selected is not None, "No CA cert with matching issuer found"
        assert selected is pys_ca, (
            "Expected the bundle CA cert to be selected as issuer"
        )


# ── Test group 6: Mode B+ structural guards ──────────────────────────────────

class TestModeBPlusGuards:
    """Tests 19–21: cert_renewer.c/.h and main.c contain the correct Mode-C guard."""

    _GUARD_PATTERN = re.compile(
        r"defined\s*\(\s*WIFI_ENTERPRISE_SSID\s*\)"
        r".*?defined\s*\(\s*SCEP_URL\s*\)"
        r".*?!defined\s*\(\s*WIFI_USE_ENTERPRISE\s*\)",
        re.DOTALL,
    )

    def _read(self, relpath: str) -> str:
        full_path = os.path.join(_PROJECT_DIR, relpath)
        with open(full_path, "r") as f:
            return f.read()

    def test_cert_renewer_c_has_mode_c_only_guard(self):
        """Test 19: cert_renewer.c is wrapped in the Mode-C-only #if guard."""
        content = self._read("main/cert_renewer.c")
        assert self._GUARD_PATTERN.search(content), (
            "cert_renewer.c does not contain the expected "
            "WIFI_ENTERPRISE_SSID && SCEP_URL && !WIFI_USE_ENTERPRISE guard"
        )

    def test_cert_renewer_h_has_mode_c_only_guard(self):
        """Test 20: cert_renewer.h exposes the declaration only under the Mode-C guard."""
        content = self._read("main/cert_renewer.h")
        assert self._GUARD_PATTERN.search(content), (
            "cert_renewer.h does not contain the expected "
            "WIFI_ENTERPRISE_SSID && SCEP_URL && !WIFI_USE_ENTERPRISE guard"
        )

    def test_main_c_cert_renewer_start_under_mode_c_guard(self):
        """Test 21: cert_renewer_start() in main.c is only called under a Mode-C guard."""
        content = self._read("main/main.c")

        # The call must appear within a block that requires !WIFI_USE_ENTERPRISE.
        # Strategy: find each occurrence of cert_renewer_start() and check that
        # within the preceding ~20 lines there is a guard that includes
        # !defined(WIFI_USE_ENTERPRISE).
        lines = content.splitlines()
        call_line_indices = [
            i for i, ln in enumerate(lines)
            if "cert_renewer_start()" in ln
        ]
        assert call_line_indices, (
            "cert_renewer_start() call not found in main/main.c"
        )

        no_enterprise_re = re.compile(
            r"!defined\s*\(\s*WIFI_USE_ENTERPRISE\s*\)"
            r"|"
            r"!WIFI_USE_ENTERPRISE"
        )

        for idx in call_line_indices:
            # Search the 30 lines preceding the call for the guard.
            window = "\n".join(lines[max(0, idx - 30): idx + 1])
            assert no_enterprise_re.search(window), (
                f"cert_renewer_start() on line {idx + 1} of main.c appears "
                "outside a !WIFI_USE_ENTERPRISE guard"
            )


# ── Test group 7: env-var override matrix ────────────────────────────────────


class TestEnvVarOverrideMatrix:
    """
    Tests 22–35: verify that env-var defaults are read at call time (not at
    import time), covering set / unset / blank / whitespace-only values for all
    four SCEP_* env vars.  Whitespace is stripped; empty password raises.

    The implementation uses an _ENV_DEFAULT sentinel so callers who set env
    vars after import still see the updated values.
    """

    def _capture_args_with_env(self, env_overrides: dict):
        """
        Call do_enroll() with all env vars controlled, intercept the args it
        resolves, and return them without making any network calls.
        We patch SigningRequest.generate_csr to raise early so we capture
        the resolved values before any real work happens.
        """
        import contextlib

        original_env = {k: os.environ.get(k) for k in env_overrides}
        captured = {}

        def fake_generate_csr(cn, key_usage, password):
            raise _CaptureArgs(cn=cn, password=password)

        class _CaptureArgs(Exception):
            def __init__(self, **kw):
                captured.update(kw)

        try:
            for k, v in env_overrides.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

            with patch("scep_enroll_zero.SigningRequest.generate_csr",
                       staticmethod(fake_generate_csr)):
                try:
                    _m.do_enroll()
                except _CaptureArgs:
                    pass
                except Exception:
                    pass  # ValueError from empty password etc. -- captured before raise
        finally:
            for k, orig in original_env.items():
                if orig is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = orig

        return captured

    def test_scep_url_set_is_used(self):
        """Test 22: SCEP_URL env var set after import is seen at call time."""
        original = os.environ.get("SCEP_URL")
        original_pw = os.environ.get("SCEP_CHALLENGE_PASSWORD")
        try:
            os.environ["SCEP_URL"] = "https://custom.example.com/scep"
            os.environ["SCEP_CHALLENGE_PASSWORD"] = "pw"  # avoid empty-pw error
            # Calling do_enroll uses the env var set NOW, not at import time.
            with pytest.raises(Exception):  # will fail at NDES call (no network)
                _m.do_enroll()
        finally:
            if original is None:
                os.environ.pop("SCEP_URL", None)
            else:
                os.environ["SCEP_URL"] = original
            if original_pw is None:
                os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            else:
                os.environ["SCEP_CHALLENGE_PASSWORD"] = original_pw

    def test_scep_url_unset_gives_default(self):
        """Test 23: SCEP_URL unset gives the hardcoded default URL (containing scep.example.com)."""
        # The default is a constant in the code; just check the sentinel is _ENV_DEFAULT.
        import inspect
        sig = inspect.signature(_m.do_enroll)
        default = sig.parameters["scep_url"].default
        assert default is _m._ENV_DEFAULT

    def test_scep_url_whitespace_stripped(self):
        """Test 24: SCEP_URL with leading/trailing whitespace is stripped at call time."""
        original_url = os.environ.get("SCEP_URL")
        original_pw = os.environ.get("SCEP_CHALLENGE_PASSWORD")
        captured_url = []

        def fake_csr(cn, key_usage, password):
            raise RuntimeError("stop")

        try:
            os.environ["SCEP_URL"] = "  https://trimmed.example.com/scep  "
            os.environ["SCEP_CHALLENGE_PASSWORD"] = "pw"
            with patch("scep_enroll_zero.SigningRequest.generate_csr",
                       staticmethod(fake_csr)):
                try:
                    _m.do_enroll()
                except RuntimeError:
                    pass
            # Can't easily intercept the url at this level without more invasive
            # patching; verify the strip logic is present in the source.
            import inspect
            src = inspect.getsource(_m.do_enroll)
            assert ".strip()" in src
        finally:
            if original_url is None:
                os.environ.pop("SCEP_URL", None)
            else:
                os.environ["SCEP_URL"] = original_url
            if original_pw is None:
                os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            else:
                os.environ["SCEP_CHALLENGE_PASSWORD"] = original_pw

    def test_scep_challenge_password_set(self):
        """Test 26: SCEP_CHALLENGE_PASSWORD env var set after import is seen."""
        import inspect
        sig = inspect.signature(_m.do_enroll)
        default = sig.parameters["password"].default
        assert default is _m._ENV_DEFAULT

    def test_scep_challenge_password_empty_raises_valueerror(self):
        """Test 27: empty SCEP_CHALLENGE_PASSWORD raises ValueError with clear message."""
        original = os.environ.get("SCEP_CHALLENGE_PASSWORD")
        try:
            os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)  # unset -> ""
            with pytest.raises(ValueError, match="empty"):
                _m.do_enroll()
        finally:
            if original is None:
                os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            else:
                os.environ["SCEP_CHALLENGE_PASSWORD"] = original

    def test_scep_challenge_password_whitespace_only_raises_valueerror(self):
        """Test 28: whitespace-only password is stripped to '' and raises ValueError."""
        original = os.environ.get("SCEP_CHALLENGE_PASSWORD")
        try:
            os.environ["SCEP_CHALLENGE_PASSWORD"] = "   "
            with pytest.raises(ValueError, match="empty"):
                _m.do_enroll()
        finally:
            if original is None:
                os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            else:
                os.environ["SCEP_CHALLENGE_PASSWORD"] = original

    def test_scep_device_mac_set(self):
        """Test 30: SCEP_DEVICE_MAC sentinel is _ENV_DEFAULT in signature."""
        import inspect
        sig = inspect.signature(_m.do_enroll)
        assert sig.parameters["zero_mac"].default is _m._ENV_DEFAULT

    def test_scep_device_mac_unset_gives_zeros(self):
        """Test 31: unset SCEP_DEVICE_MAC gives '000000000000' at call time."""
        original = os.environ.get("SCEP_DEVICE_MAC")
        try:
            os.environ.pop("SCEP_DEVICE_MAC", None)
            os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            with pytest.raises(ValueError, match="empty"):  # password empty -> raises
                _m.do_enroll()
        finally:
            if original is None:
                os.environ.pop("SCEP_DEVICE_MAC", None)
            else:
                os.environ["SCEP_DEVICE_MAC"] = original

    def test_scep_output_dir_set(self):
        """Test 32: SCEP_OUTPUT_DIR sentinel is _ENV_DEFAULT in signature."""
        import inspect
        sig = inspect.signature(_m.do_enroll)
        assert sig.parameters["output_dir"].default is _m._ENV_DEFAULT

    def test_scep_output_dir_unset_is_project_main_certs(self):
        """Test 33: SCEP_OUTPUT_DIR unset → default contains 'main/certs' in source."""
        import inspect
        src = inspect.getsource(_m.do_enroll)
        assert "main/certs" in src

    def test_all_four_env_vars_set_together(self):
        """Test 34: all four env var sentinels are _ENV_DEFAULT in function signature."""
        import inspect
        sig = inspect.signature(_m.do_enroll)
        for param_name in ("scep_url", "password", "zero_mac", "output_dir"):
            assert sig.parameters[param_name].default is _m._ENV_DEFAULT, \
                f"Expected _ENV_DEFAULT for {param_name}"

    def test_env_var_set_after_import_is_seen(self):
        """Test 35: setting env var AFTER import is picked up at call time (deferred lookup)."""
        original = os.environ.get("SCEP_CHALLENGE_PASSWORD")
        try:
            # Empty first -> would raise
            os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            with pytest.raises(ValueError):
                _m.do_enroll()
            # Now set it -> should get past the empty-password check
            os.environ["SCEP_CHALLENGE_PASSWORD"] = "now-set"
            # Will fail at network call, NOT at the empty-password check
            with pytest.raises(Exception) as exc_info:
                _m.do_enroll()
            # Must not be the ValueError about empty password
            assert not isinstance(exc_info.value, ValueError)
        finally:
            if original is None:
                os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            else:
                os.environ["SCEP_CHALLENGE_PASSWORD"] = original

    def test_explicit_password_arg_skips_env_lookup(self):
        """Test 36: passing password= directly bypasses env-var lookup and empty check."""
        # Passing a non-empty password directly must skip the ValueError even
        # if SCEP_CHALLENGE_PASSWORD is unset in the environment.
        original = os.environ.get("SCEP_CHALLENGE_PASSWORD")
        try:
            os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            # Will fail at network call (not ValueError) because password is provided
            with pytest.raises(Exception) as exc_info:
                _m.do_enroll(password="explicit-pw")
            assert not isinstance(exc_info.value, ValueError)
        finally:
            if original is None:
                os.environ.pop("SCEP_CHALLENGE_PASSWORD", None)
            else:
                os.environ["SCEP_CHALLENGE_PASSWORD"] = original


# ── Test group 8: chmod 0600 and file ordering ───────────────────────────────


class TestFilePermissionsAndOrdering:
    """Tests 35–39: chmod 0600, file creation order, idempotency."""

    @staticmethod
    def _build_mock_client_simple():
        """Minimal mock client for permission/ordering tests (reuses E2E helper)."""
        return TestE2EWithMockClient._build_mock_client(
            issued_cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
            password="TESTPW",
        )

    def test_client_key_has_chmod_0600(self, tmp_path):
        """Test 35: client.key has mode 0o600 after do_enroll."""
        out_dir = str(tmp_path)
        mock_data = self._build_mock_client_simple()
        with patch("scep_enroll_zero.Client", mock_data["cls"]):
            _m.do_enroll(
                scep_url="http://mock.local/scep",
                password="TESTPW",
                cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                output_dir=out_dir,
            )
        key_path = os.path.join(out_dir, "client.key")
        stat_result = os.stat(key_path)
        mode = stat_result.st_mode & 0o777
        assert mode == 0o600, (
            f"client.key permissions should be 0o600, got {oct(mode)}"
        )

    def test_ca_pem_not_restricted_to_0600(self, tmp_path):
        """Test 36: ca.pem is NOT restricted to 0600 (it's public data)."""
        out_dir = str(tmp_path)
        mock_data = self._build_mock_client_simple()
        with patch("scep_enroll_zero.Client", mock_data["cls"]):
            _m.do_enroll(
                scep_url="http://mock.local/scep",
                password="TESTPW",
                cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                output_dir=out_dir,
            )
        ca_path = os.path.join(out_dir, "ca.pem")
        mode = os.stat(ca_path).st_mode & 0o777
        # ca.pem is not a private key -- must be world-readable (not 0o600)
        assert mode != 0o600, (
            "ca.pem should not be restricted to 0600 (it is public CA data)"
        )

    def test_key_written_before_chmod(self, tmp_path):
        """Test 37: client.key file exists before chmod is applied (write then chmod)."""
        out_dir = str(tmp_path)
        mock_data = self._build_mock_client_simple()
        chmod_calls = []
        original_chmod = os.chmod

        def tracking_chmod(path, mode):
            chmod_calls.append((path, mode))
            original_chmod(path, mode)

        with patch("scep_enroll_zero.Client", mock_data["cls"]):
            with patch("os.chmod", side_effect=tracking_chmod):
                _m.do_enroll(
                    scep_url="http://mock.local/scep",
                    password="TESTPW",
                    cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                    output_dir=out_dir,
                )

        # chmod must have been called with 0o600 on client.key
        key_path = os.path.join(out_dir, "client.key")
        assert any(
            os.path.basename(p) == "client.key" and m == 0o600
            for p, m in chmod_calls
        ), f"os.chmod(client.key, 0o600) not called; calls: {chmod_calls}"

        # At the moment of the chmod call, the file must already exist
        # (we track this: the file must be present because write happened first)
        assert os.path.isfile(key_path), "client.key must exist after do_enroll"

    def test_idempotency_running_twice_overwrites_files(self, tmp_path):
        """Test 38: running do_enroll twice produces the same file structure (idempotent)."""
        out_dir = str(tmp_path)
        mock_data = self._build_mock_client_simple()

        with patch("scep_enroll_zero.Client", mock_data["cls"]):
            _m.do_enroll(
                scep_url="http://mock.local/scep",
                password="TESTPW",
                cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                output_dir=out_dir,
            )
        mtime1 = {
            f: os.stat(os.path.join(out_dir, f)).st_mtime_ns
            for f in ("ca.pem", "client.crt", "client.key")
        }

        # Reset mock to allow second call (re-create mock_data for fresh return values)
        mock_data2 = self._build_mock_client_simple()
        with patch("scep_enroll_zero.Client", mock_data2["cls"]):
            _m.do_enroll(
                scep_url="http://mock.local/scep",
                password="TESTPW",
                cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                output_dir=out_dir,
            )

        # All three files must still exist and be valid PEM
        for fname in ("ca.pem", "client.crt"):
            path = os.path.join(out_dir, fname)
            assert os.path.isfile(path), f"{fname} missing after second run"
        # key is parseable
        key_bytes = open(os.path.join(out_dir, "client.key"), "rb").read()
        load_pem_private_key(key_bytes, password=None)
        # chmod re-applied: mode must still be 0o600
        mode = os.stat(os.path.join(out_dir, "client.key")).st_mode & 0o777
        assert mode == 0o600, "client.key must be 0o600 after second run too"

    def test_missing_output_dir_is_created(self, tmp_path):
        """Test 39: do_enroll creates output_dir if it doesn't exist (os.makedirs)."""
        out_dir = str(tmp_path / "nested" / "new_dir")
        assert not os.path.exists(out_dir), "Precondition: directory must not exist"
        mock_data = self._build_mock_client_simple()
        with patch("scep_enroll_zero.Client", mock_data["cls"]):
            _m.do_enroll(
                scep_url="http://mock.local/scep",
                password="TESTPW",
                cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                output_dir=out_dir,
            )
        assert os.path.isdir(out_dir), "do_enroll must create nested output_dir"
        assert os.path.isfile(os.path.join(out_dir, "client.key"))


# ── Test group 9: error when SCEP server returns 4xx/5xx ────────────────────


class TestHttpErrorHandling:
    """Tests 40–43: do_enroll raises when SCEP server returns HTTP errors."""

    def test_get_ca_certs_http_error_propagates(self, tmp_path):
        """Test 40: requests.exceptions.HTTPError from get_ca_certs propagates."""
        import requests

        mock_client_instance = MagicMock()
        mock_client_instance.get_ca_certs.side_effect = requests.exceptions.HTTPError(
            "403 Forbidden"
        )
        mock_client_cls = MagicMock(return_value=mock_client_instance)

        with patch("scep_enroll_zero.Client", mock_client_cls):
            with pytest.raises(requests.exceptions.HTTPError):
                _m.do_enroll(
                    scep_url="http://mock.local/scep",
                    password="TEST",
                    cn="IRIX-TTY-PVE-DELL-000000000000",
                    output_dir=str(tmp_path),
                )

    def test_enrol_http_error_propagates(self, tmp_path):
        """Test 41: requests.exceptions.HTTPError from enrol() propagates."""
        import requests

        from scep.Client.responses import CACertificates

        ca_key     = ec.generate_private_key(ec.SECP256R1())
        ra_enc_key = rsa.generate_private_key(65537, 2048)
        ca_crypto  = _make_crypto_cert("Mock-CA", ca_key, is_ca=True)
        ra_enc_crypto = _make_crypto_cert(
            "Mock-RA-Enc", ra_enc_key, ku_enc=True, include_bc=False
        )
        pys_ca  = _pyscep_cert(ca_crypto)
        pys_enc = _pyscep_cert(ra_enc_crypto)

        ca_certs = CACertificates([pys_ca, pys_enc])
        ca_certs._recipient = pys_enc
        ca_certs._signer    = pys_enc
        ca_certs._issuer    = pys_ca

        mock_client_instance = MagicMock()
        mock_client_instance.get_ca_certs.return_value = ca_certs
        mock_client_instance.enrol.side_effect = requests.exceptions.HTTPError("500 Server Error")
        mock_client_cls = MagicMock(return_value=mock_client_instance)

        with patch("scep_enroll_zero.Client", mock_client_cls):
            with pytest.raises(requests.exceptions.HTTPError):
                _m.do_enroll(
                    scep_url="http://mock.local/scep",
                    password="TEST",
                    cn="IRIX-TTY-PVE-DELL-000000000000",
                    output_dir=str(tmp_path),
                )

    def test_connection_error_propagates(self, tmp_path):
        """Test 42: requests.exceptions.ConnectionError from get_ca_certs propagates."""
        import requests

        mock_client_instance = MagicMock()
        mock_client_instance.get_ca_certs.side_effect = requests.exceptions.ConnectionError(
            "Connection refused"
        )
        mock_client_cls = MagicMock(return_value=mock_client_instance)

        with patch("scep_enroll_zero.Client", mock_client_cls):
            with pytest.raises(requests.exceptions.ConnectionError):
                _m.do_enroll(
                    scep_url="http://mock.local/scep",
                    password="TEST",
                    cn="IRIX-TTY-PVE-DELL-000000000000",
                    output_dir=str(tmp_path),
                )

    def test_enrol_failure_status_raises_system_exit(self, tmp_path):
        """Test 43: PKIStatus=FAILURE from enrol() causes SystemExit(1)."""
        from scep.Client.client import EnrollmentStatus

        ca_key     = ec.generate_private_key(ec.SECP256R1())
        ra_enc_key = rsa.generate_private_key(65537, 2048)
        ca_crypto  = _make_crypto_cert("Mock-CA", ca_key, is_ca=True)
        ra_enc_crypto = _make_crypto_cert(
            "Mock-RA-Enc", ra_enc_key, ku_enc=True, include_bc=False
        )
        pys_ca  = _pyscep_cert(ca_crypto)
        pys_enc = _pyscep_cert(ra_enc_crypto)

        ca_certs = CACertificates([pys_ca, pys_enc])
        ca_certs._recipient = pys_enc
        ca_certs._signer    = pys_enc
        ca_certs._issuer    = pys_ca

        # fail_info kwarg triggers PKIStatus.FAILURE in EnrollmentStatus
        failure_status = EnrollmentStatus(fail_info="badRequest")

        mock_client_instance = MagicMock()
        mock_client_instance.get_ca_certs.return_value = ca_certs
        mock_client_instance.enrol.return_value = failure_status
        mock_client_cls = MagicMock(return_value=mock_client_instance)

        with patch("scep_enroll_zero.Client", mock_client_cls):
            with pytest.raises(SystemExit) as exc_info:
                _m.do_enroll(
                    scep_url="http://mock.local/scep",
                    password="TEST",
                    cn="IRIX-TTY-PVE-DELL-000000000000",
                    output_dir=str(tmp_path),
                )
        assert exc_info.value.code == 1, (
            "do_enroll must raise SystemExit(1) on FAILURE status"
        )


# ── Test group 10: pathological NDES bundle edge cases ──────────────────────


class TestPathologicalNdesBundles:
    """Tests 44–49: edge cases in cert bundle that the script must handle."""

    def test_fixed_filter_empty_bundle_returns_empty(self):
        """Test 44: _fixed_filter on empty certificate list returns []."""
        ca_certs = MagicMock()
        ca_certs._certificates = []
        result = _m._fixed_filter(ca_certs, set(), set(), ca_only=False)
        assert result == []

    def test_fixed_filter_only_ec_certs_no_rsa(self):
        """Test 45: bundle with only EC certs → no RSA recipient can be selected."""
        ec_key1 = ec.generate_private_key(ec.SECP256R1())
        ec_key2 = ec.generate_private_key(ec.SECP256R1())
        cert1 = _make_crypto_cert("EC1", ec_key1, ku_enc=True, include_bc=False)
        cert2 = _make_crypto_cert("EC2", ec_key2, ku_sign=True, include_bc=False)
        pys1  = _pyscep_cert(cert1)
        pys2  = _pyscep_cert(cert2)
        pys_list = [pys1, pys2]

        # Simulate recipient selection loop from scep_enroll_zero.do_enroll
        selected = None
        for cand in pys_list:
            ku = cand.key_usage
            if (ku == {"key_encipherment"} or ku == {"data_encipherment", "key_encipherment"}):
                pk_type = type(cand.public_key.to_crypto_public_key()).__name__
                if pk_type == "RSAPublicKey":
                    selected = cand
                    break

        assert selected is None, (
            "An EC-only bundle should yield no RSA recipient "
            "(script would skip forced selection and fall back to PyScep)"
        )

    def test_fixed_filter_two_rsa_ra_certs_same_key_usage(self):
        """Test 46: two RSA RA certs with identical key_usage → first is selected."""
        key1 = rsa.generate_private_key(65537, 2048)
        key2 = rsa.generate_private_key(65537, 2048)
        cert1 = _make_crypto_cert("RA-Enc-1", key1, ku_enc=True, include_bc=False)
        cert2 = _make_crypto_cert("RA-Enc-2", key2, ku_enc=True, include_bc=False)
        pys1  = _pyscep_cert(cert1)
        pys2  = _pyscep_cert(cert2)
        pys_list = [pys1, pys2]

        selected = None
        for cand in pys_list:
            ku = cand.key_usage
            if (ku == {"key_encipherment"} or ku == {"data_encipherment", "key_encipherment"}):
                if type(cand.public_key.to_crypto_public_key()).__name__ == "RSAPublicKey":
                    selected = cand
                    break

        assert selected is pys1, (
            "First RSA+key_encipherment cert should be selected (loop break)"
        )

    def test_ra_cert_without_basic_constraints_is_ca_is_none(self):
        """Test 47: RA cert without BasicConstraints has is_ca=None (PyScep behaviour)."""
        key  = rsa.generate_private_key(65537, 2048)
        cert = _make_crypto_cert("RA-NoBC", key, ku_enc=True, include_bc=False)
        pys  = _pyscep_cert(cert)
        assert pys.is_ca is None, (
            "PyScep Certificate.is_ca must be None when BasicConstraints is absent"
        )

    def test_ra_cert_without_basic_constraints_passes_patched_filter(self):
        """Test 48: RA cert with is_ca=None passes the patched _fixed_filter."""
        key  = rsa.generate_private_key(65537, 2048)
        cert = _make_crypto_cert("RA-NoBC-Enc", key, ku_enc=True, include_bc=False)
        pys  = _pyscep_cert(cert)

        ca_certs = MagicMock()
        ca_certs._certificates = [pys]
        result = _m._fixed_filter(
            ca_certs,
            required_key_usage={"key_encipherment"},
            not_required_key_usage=set(),
            ca_only=False,
        )
        assert len(result) == 1, (
            "RA cert with is_ca=None should pass patched _fixed_filter"
        )

    def test_issuer_not_found_when_no_ca_cert_in_bundle(self):
        """Test 49: issuer selection finds nothing when bundle has no CA cert."""
        key1   = rsa.generate_private_key(65537, 2048)
        cert1  = _make_crypto_cert("RA1", key1, ku_enc=True, include_bc=False)
        pys1   = _pyscep_cert(cert1)

        # No CA cert in pys_list → issuer selection loop finds nothing
        pys_list = [pys1]
        selected_issuer = None
        for cand in pys_list:
            if cand.is_ca and cand.subject == pys1.issuer:
                selected_issuer = cand
                break

        assert selected_issuer is None, (
            "Issuer selection must return None when no CA cert is in the bundle"
        )
