#!/usr/bin/env python3
"""
test/scripts/test_scep_enroll_zero_paths.py
===========================================
Focused tests for the S-F4 path-portability fix in
scripts/scep_enroll_zero.py.

The audited bug (S-F4): two paths were hardcoded to the author's machine:

  * the default output_dir was "/root/esp-tty/main/certs"
  * REQUESTS_CA_BUNDLE was set unconditionally to
    "/root/esp-tty/main/certs/scep_ca.pem"

Both break on any other checkout location, and pointing REQUESTS_CA_BUNDLE
at a nonexistent file makes `requests` raise SSLError (and disables the
system trust store entirely).

The fix:
  * derive paths relative to the script's __file__ (scripts/ -> ../main/certs)
  * only setdefault REQUESTS_CA_BUNDLE when the resolved bundle file exists

These tests lock both behaviours in.  They reuse the mock-Client helpers
from test_scep_enroll_zero (no network), and run do_enroll() to an isolated
temp output dir so the real main/certs tree is never touched.

No network, no hardware, no ESP-IDF required.
Run with:
    venv/bin/pytest test/scripts/test_scep_enroll_zero_paths.py -v
"""

import os
import sys

import pytest

# ── Make scripts/ importable ──────────────────────────────────────────────────
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS_DIR = os.path.abspath(os.path.join(_TEST_DIR, "..", "..", "scripts"))
_PROJECT_DIR = os.path.abspath(os.path.join(_TEST_DIR, "..", ".."))
sys.path.insert(0, _SCRIPTS_DIR)
# The mock-Client helpers live in the sibling test module.
sys.path.insert(0, _TEST_DIR)

import scep_enroll_zero as _m  # noqa: E402

# Reuse the cert-builder helpers + mock infra from the main test module.
from scep.Client.responses import CACertificates  # noqa: E402
from scep.Client.client import EnrollmentStatus  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa, ec  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

from test_scep_enroll_zero import _make_crypto_cert, _pyscep_cert  # noqa: E402

_EXPECTED_CERTS_DIR = os.path.normpath(
    os.path.join(_PROJECT_DIR, "main", "certs")
)


# ── Mock Client (no network) ─────────────────────────────────────────────────
def _build_mock_client(issued_cn, password):
    """Minimal mock so do_enroll() runs end-to-end with no network.

    Mirrors the bundle shape do_enroll expects: an EC CA, an RSA RA-enc
    (key_encipherment) cert, an RSA RA-sign (digital_signature) cert, and an
    RSA issued leaf signed by the CA.
    """
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
        issued_cn, issued_key, signing_key=ca_key, issuer_name=ca_name,
    )

    ca_certs = CACertificates([
        _pyscep_cert(ca_crypto),
        _pyscep_cert(ra_enc_crypto),
        _pyscep_cert(ra_sign_crypto),
    ])
    ca_certs._recipient = _pyscep_cert(ra_enc_crypto)
    ca_certs._signer    = _pyscep_cert(ra_sign_crypto)
    ca_certs._issuer    = _pyscep_cert(ca_crypto)

    inst = MagicMock()
    inst.get_ca_certs.return_value = ca_certs
    inst.enrol.return_value = EnrollmentStatus(
        certificates=[_pyscep_cert(issued_crypto)]
    )
    return MagicMock(return_value=inst)


@pytest.fixture(autouse=True)
def _isolate_requests_ca_bundle():
    """Save/restore REQUESTS_CA_BUNDLE so tests don't leak into each other."""
    saved = os.environ.get("REQUESTS_CA_BUNDLE")
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    try:
        yield
    finally:
        os.environ.pop("REQUESTS_CA_BUNDLE", None)
        if saved is not None:
            os.environ["REQUESTS_CA_BUNDLE"] = saved


# ---------------------------------------------------------------------------
# 1. Module-level _CERTS_DIR is repo-relative, not a hardcoded /root path.
# ---------------------------------------------------------------------------
def test_certs_dir_is_repo_relative():
    assert hasattr(_m, "_CERTS_DIR"), \
        "_CERTS_DIR constant missing (S-F4 regression)"
    assert _m._CERTS_DIR == _EXPECTED_CERTS_DIR, (
        f"_CERTS_DIR={_m._CERTS_DIR!r} should resolve to {_EXPECTED_CERTS_DIR!r} "
        "relative to the script (S-F4 regression)"
    )
    assert os.path.isabs(_m._CERTS_DIR)


# ---------------------------------------------------------------------------
# 2. No hardcoded author-machine paths remain in the source.
# ---------------------------------------------------------------------------
def test_no_hardcoded_root_paths_in_source():
    src_path = os.path.join(_SCRIPTS_DIR, "scep_enroll_zero.py")
    with open(src_path, "r") as f:
        src = f.read()
    assert "/root/esp-tty" not in src, \
        "hardcoded /root/esp-tty path still present (S-F4 regression)"


# ---------------------------------------------------------------------------
# 3. Default output_dir (no SCEP_OUTPUT_DIR env) resolves to repo _CERTS_DIR.
#    We don't want to actually write into main/certs, so we assert the
#    resolution by monkeypatching makedirs/open targets via a sentinel dir
#    -- instead, the simplest deterministic check: the env default falls back
#    to _CERTS_DIR.  Verified through a partial run that captures os.makedirs.
# ---------------------------------------------------------------------------
def test_default_output_dir_falls_back_to_repo_certs(monkeypatch):
    monkeypatch.delenv("SCEP_OUTPUT_DIR", raising=False)

    captured = {}

    # do_enroll resolves output_dir, runs the (mocked) enrolment, then calls
    # os.makedirs(output_dir) just before writing the PEM files.  We stop the
    # run there so we capture the resolved path without ever writing into the
    # real main/certs tree.
    class _Stop(Exception):
        pass

    def _stop_makedirs(path, *a, **k):
        captured["output_dir"] = path
        raise _Stop()

    monkeypatch.setattr(_m.os, "makedirs", _stop_makedirs)

    mock_cls = _build_mock_client("IRIX-TTY-PVE-DELL-aabbccddeeff", "PW")
    with patch("scep_enroll_zero.Client", mock_cls):
        with pytest.raises(_Stop):
            _m.do_enroll(
                scep_url="http://mock.local/scep",
                password="PW",
                cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
                # output_dir omitted -> falls back to env / _CERTS_DIR default
            )

    assert captured["output_dir"] == _EXPECTED_CERTS_DIR, (
        f"default output_dir={captured['output_dir']!r} should be "
        f"{_EXPECTED_CERTS_DIR!r} (S-F4 regression)"
    )


# ---------------------------------------------------------------------------
# 4. REQUESTS_CA_BUNDLE is set only when the bundle file exists, and to the
#    repo-relative path.
# ---------------------------------------------------------------------------
def test_requests_ca_bundle_set_when_bundle_exists(tmp_path, monkeypatch):
    # Point _CERTS_DIR at a temp dir that DOES contain scep_ca.pem.
    fake_certs = tmp_path / "certs"
    fake_certs.mkdir()
    bundle = fake_certs / "scep_ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(_m, "_CERTS_DIR", str(fake_certs))

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    mock_cls = _build_mock_client("IRIX-TTY-PVE-DELL-aabbccddeeff", "PW")
    with patch("scep_enroll_zero.Client", mock_cls):
        _m.do_enroll(
            scep_url="http://mock.local/scep",
            password="PW",
            cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
            output_dir=str(out_dir),
        )

    assert os.environ.get("REQUESTS_CA_BUNDLE") == str(bundle), (
        "REQUESTS_CA_BUNDLE should be set to the existing repo-relative "
        "bundle (S-F4 regression)"
    )


def test_requests_ca_bundle_unset_when_bundle_missing(tmp_path, monkeypatch):
    # Point _CERTS_DIR at a temp dir with NO scep_ca.pem.
    fake_certs = tmp_path / "certs"
    fake_certs.mkdir()
    assert not (fake_certs / "scep_ca.pem").exists()
    monkeypatch.setattr(_m, "_CERTS_DIR", str(fake_certs))

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    mock_cls = _build_mock_client("IRIX-TTY-PVE-DELL-aabbccddeeff", "PW")
    with patch("scep_enroll_zero.Client", mock_cls):
        _m.do_enroll(
            scep_url="http://mock.local/scep",
            password="PW",
            cn="IRIX-TTY-PVE-DELL-aabbccddeeff",
            output_dir=str(out_dir),
        )

    assert "REQUESTS_CA_BUNDLE" not in os.environ, (
        "REQUESTS_CA_BUNDLE must NOT be set when the bundle file is absent "
        "(setting it to a missing path breaks TLS) (S-F4 regression)"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
