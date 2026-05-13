#!/usr/bin/env python3
"""
test/scripts/test_ota_send_unit.py -- Pure-Python unit tests for the crypto
helpers in scripts/ota_send.py.

These tests exercise:
  * derive_key()       -- HKDF-SHA256 over X25519 shared secret, both as a
                          known-answer test and as a "client and device derive
                          the same key from swapped roles" symmetry test
  * encrypt_firmware() -- AES-256-GCM roundtrip + IV/tag length contract
  * HKDF_SALT          -- must exactly match what main/ota_session.c hard-codes
                          (b"esp-tty-ota-v2", 14 bytes, no trailing NUL)

No SSH, no network, no hardware required.  Run with:
    venv/bin/pytest test/scripts/test_ota_send_unit.py -v
"""

import os
import sys

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Make scripts/ importable.
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PROJECT_DIR, "scripts"))

import ota_send  # noqa: E402


# ---- Salt sanity --------------------------------------------------------------

def test_hkdf_salt_matches_device_firmware():
    # main/ota_session.c hard-codes b"esp-tty-ota-v2" (14 bytes, no NUL).
    # If this ever drifts, the device will derive a different key and every
    # OTA upload will fail with "auth tag verify failed".
    assert ota_send.HKDF_SALT == b"esp-tty-ota-v2"
    assert len(ota_send.HKDF_SALT) == 14
    assert b"\x00" not in ota_send.HKDF_SALT


def test_protocol_constants():
    assert ota_send.PROTO_VERSION == 0x02
    assert ota_send.X25519_LEN == 32
    assert ota_send.IV_LEN == 12
    assert ota_send.TAG_LEN == 16


# ---- derive_key() -------------------------------------------------------------

def test_derive_key_returns_correct_shapes():
    client_priv = X25519PrivateKey.generate()
    device_priv = X25519PrivateKey.generate()
    device_pub = device_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    client_pub, aes_key = ota_send.derive_key(client_priv, device_pub)
    assert isinstance(client_pub, bytes) and len(client_pub) == 32
    assert isinstance(aes_key, bytes) and len(aes_key) == 32


def test_derive_key_known_answer_with_fixed_inputs():
    """
    Both peers, fed deterministic private scalars, must derive the exact same
    32-byte AES key.  We compute the expected key independently below using
    cryptography's HKDF primitive (mirroring what the device's wc_HKDF would do)
    and compare byte-for-byte.
    """
    # Two arbitrary fixed 32-byte X25519 private scalars.  X25519PrivateKey
    # accepts any 32 bytes and clamps internally per RFC 7748, so these
    # constants give a fully reproducible exchange.
    client_priv_bytes = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    device_priv_bytes = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

    client_priv = X25519PrivateKey.from_private_bytes(client_priv_bytes)
    device_priv = X25519PrivateKey.from_private_bytes(device_priv_bytes)

    client_pub = client_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    device_pub = device_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    # X25519 published test vectors give the shared secret for these scalars:
    expected_shared = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert client_priv.exchange(
        X25519PublicKey.from_public_bytes(device_pub)) == expected_shared

    # Independent HKDF computation -- mirrors what the device does.
    expected_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"esp-tty-ota-v2",
        info=client_pub + device_pub,
    ).derive(expected_shared)

    # The function under test must agree.
    got_pub, got_key = ota_send.derive_key(client_priv, device_pub)
    assert got_pub == client_pub
    assert got_key == expected_key


def test_derive_key_symmetry_client_and_device_agree():
    """
    The OTA protocol relies on both ends computing the same AES key.  Here we
    simulate the device side by hand (mirroring main/ota_session.c's HKDF call:
    salt=HKDF_SALT, info=client_pub || device_pub) and require it to match the
    client-side helper.
    """
    client_priv = X25519PrivateKey.generate()
    device_priv = X25519PrivateKey.generate()

    client_pub_bytes = client_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    device_pub_bytes = device_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    # -- Client side (the function under test).
    got_client_pub, client_key = ota_send.derive_key(
        client_priv, device_pub_bytes)
    assert got_client_pub == client_pub_bytes

    # -- Device side (simulated): same HKDF parameters with the roles swapped.
    shared = device_priv.exchange(
        X25519PublicKey.from_public_bytes(client_pub_bytes))
    device_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ota_send.HKDF_SALT,
        info=client_pub_bytes + device_pub_bytes,
    ).derive(shared)

    assert client_key == device_key


def test_derive_key_changes_with_different_peer():
    """Two different device pubkeys must yield different derived AES keys."""
    client_priv = X25519PrivateKey.generate()
    dev1 = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    dev2 = X25519PrivateKey.generate().public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    _, k1 = ota_send.derive_key(client_priv, dev1)
    _, k2 = ota_send.derive_key(client_priv, dev2)
    assert k1 != k2


# ---- encrypt_firmware() -------------------------------------------------------

def test_encrypt_firmware_roundtrip():
    aes_key = os.urandom(32)
    firmware = os.urandom(4321)
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)

    assert len(iv) == 12
    assert len(tag) == 16
    assert len(ciphertext) == len(firmware)
    assert ciphertext != firmware  # actually encrypted

    # Verify by independent AES-GCM decrypt: cryptography expects ct||tag.
    plain = AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
    assert plain == firmware


def test_encrypt_firmware_fixed_iv_is_deterministic():
    aes_key = bytes(range(32))
    firmware = b"hello esp-tty over the air"
    iv = bytes(12)  # all zeros -- never use in production, but fine for tests

    iv1, tag1, ct1 = ota_send.encrypt_firmware(aes_key, firmware, iv=iv)
    iv2, tag2, ct2 = ota_send.encrypt_firmware(aes_key, firmware, iv=iv)
    assert iv1 == iv2 == iv
    assert tag1 == tag2
    assert ct1 == ct2


def test_encrypt_firmware_random_iv_differs():
    aes_key = os.urandom(32)
    firmware = b"x" * 1024
    iv_a, _, ct_a = ota_send.encrypt_firmware(aes_key, firmware)
    iv_b, _, ct_b = ota_send.encrypt_firmware(aes_key, firmware)
    # Random IVs almost certainly differ; ciphertext therefore differs too.
    assert iv_a != iv_b
    assert ct_a != ct_b


def test_encrypt_firmware_tamper_detection():
    aes_key = os.urandom(32)
    firmware = b"payload" * 100
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)

    bad = bytearray(ciphertext)
    bad[len(bad) // 2] ^= 0x01
    with pytest.raises(Exception):
        AESGCM(aes_key).decrypt(iv, bytes(bad) + tag, None)
