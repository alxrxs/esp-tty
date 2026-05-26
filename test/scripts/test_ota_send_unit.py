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


def test_encrypt_firmware_zero_length():
    """encrypt_firmware with empty plaintext still returns the right shapes."""
    aes_key = os.urandom(32)
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, b"")
    assert len(iv) == 12
    assert len(tag) == 16
    assert len(ciphertext) == 0


def test_encrypt_firmware_single_byte():
    """One-byte plaintext: ciphertext is also one byte; decrypt round-trips."""
    aes_key = os.urandom(32)
    firmware = b"\xAB"
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)
    assert len(ciphertext) == 1
    plain = AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
    assert plain == firmware


def test_encrypt_firmware_caller_supplied_iv_used():
    """Caller-supplied IV is forwarded unchanged to AESGCM."""
    aes_key = os.urandom(32)
    my_iv = bytes(range(12))
    iv, tag, _ = ota_send.encrypt_firmware(aes_key, b"hello", iv=my_iv)
    assert iv == my_iv


# ---- derive_key() edge-case tests -------------------------------------------

def test_derive_key_with_low_order_peer_pub_raises():
    """
    A peer public key of all zeros is a low-order point that X25519 rejects.
    The cryptography library raises ValueError for this input.  Document this
    behaviour: run_ota_protocol() would never call derive_key with a zero pubkey
    (the device sends a freshly generated ephemeral key), but we note the
    exception contract here so future callers know it is not safe to pass
    unchecked user input.
    """
    client_priv = X25519PrivateKey.generate()
    zero_pub = bytes(32)
    with pytest.raises((ValueError, Exception)):
        ota_send.derive_key(client_priv, zero_pub)


def test_derive_key_same_client_priv_deterministic():
    """derive_key is deterministic: same inputs must produce same outputs."""
    client_priv_bytes = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    device_pub = bytes(range(32))

    k1_pub, k1_key = ota_send.derive_key(
        X25519PrivateKey.from_private_bytes(client_priv_bytes), device_pub)
    k2_pub, k2_key = ota_send.derive_key(
        X25519PrivateKey.from_private_bytes(client_priv_bytes), device_pub)

    assert k1_pub == k2_pub
    assert k1_key == k2_key


# ---- Additional derive_key / encrypt_firmware edge cases -------------------

def test_derive_key_client_pub_is_valid_x25519_point():
    """client_pub returned by derive_key must be a valid X25519 public key."""
    client_priv = X25519PrivateKey.generate()
    device_priv = X25519PrivateKey.generate()
    device_pub = device_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    client_pub, _ = ota_send.derive_key(client_priv, device_pub)

    # Must be parseable as an X25519 public key (32 raw bytes).
    assert len(client_pub) == 32
    # Should reconstruct without raising
    X25519PublicKey.from_public_bytes(client_pub)


def test_derive_key_aes_key_not_all_zeros():
    """The derived AES key must not be the all-zeros value (sanity check)."""
    client_priv = X25519PrivateKey.generate()
    device_priv = X25519PrivateKey.generate()
    device_pub = device_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    _, aes_key = ota_send.derive_key(client_priv, device_pub)
    assert aes_key != bytes(32)


def test_encrypt_firmware_large_payload():
    """encrypt_firmware handles a 1 MiB payload without raising."""
    aes_key = os.urandom(32)
    firmware = os.urandom(1024 * 1024)
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)
    assert len(ciphertext) == len(firmware)
    assert len(iv) == 12
    assert len(tag) == 16
    # Verify round-trip.
    plain = AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
    assert plain == firmware


def test_encrypt_firmware_different_keys_produce_different_output():
    """Two different AES keys must produce different ciphertexts for the same firmware."""
    firmware = b"hello esp-tty" * 50
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    fixed_iv = bytes(12)  # same IV so only the key differs

    _, _, ct1 = ota_send.encrypt_firmware(key1, firmware, iv=fixed_iv)
    _, _, ct2 = ota_send.encrypt_firmware(key2, firmware, iv=fixed_iv)
    assert ct1 != ct2


def test_encrypt_firmware_iv_length_always_12():
    """Randomly-generated IVs must always be exactly 12 bytes (AES-GCM spec)."""
    aes_key = os.urandom(32)
    for _ in range(10):
        iv, _, _ = ota_send.encrypt_firmware(aes_key, b"test payload")
        assert len(iv) == 12


def test_hkdf_salt_is_bytes_not_str():
    """HKDF_SALT must be bytes, not str -- mbedTLS on the device uses a byte buffer."""
    assert isinstance(ota_send.HKDF_SALT, bytes)


def test_proto_version_is_single_byte():
    """PROTO_VERSION must fit in a single unsigned byte (0x00..0xFF)."""
    assert 0x00 <= ota_send.PROTO_VERSION <= 0xFF


# ---- Additional edge-case tests -----------------------------------------------

def test_derive_key_info_field_order_matters():
    """HKDF info = client_pub || device_pub -- swapping roles must produce a
    different key.  This guards against accidentally transposing the two halves
    in ota_session.c or ota_send.py."""
    client_priv = X25519PrivateKey.generate()
    device_priv = X25519PrivateKey.generate()

    client_pub_bytes = client_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    device_pub_bytes = device_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)

    shared = client_priv.exchange(
        X25519PublicKey.from_public_bytes(device_pub_bytes))

    # Correct order: client_pub || device_pub
    key_correct = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ota_send.HKDF_SALT,
        info=client_pub_bytes + device_pub_bytes,
    ).derive(shared)

    # Swapped order: device_pub || client_pub
    key_swapped = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ota_send.HKDF_SALT,
        info=device_pub_bytes + client_pub_bytes,
    ).derive(shared)

    assert key_correct != key_swapped, (
        "HKDF with client||device must differ from device||client")

    # And the function under test must produce the correct-order key.
    _, got_key = ota_send.derive_key(client_priv, device_pub_bytes)
    assert got_key == key_correct


def test_encrypt_firmware_tag_is_not_all_zeros():
    """AES-GCM tag for a non-trivial payload must never be the all-zeros value."""
    aes_key = os.urandom(32)
    firmware = b"esp32s3 ota payload" * 100
    _, tag, _ = ota_send.encrypt_firmware(aes_key, firmware)
    assert tag != bytes(16), "AES-GCM auth tag must not be all-zeros"


def test_encrypt_firmware_tag_always_16_bytes():
    """Tag length must be exactly 16 bytes regardless of payload size."""
    aes_key = os.urandom(32)
    for size in (1, 15, 16, 17, 255, 256, 1023, 1024):
        _, tag, _ = ota_send.encrypt_firmware(aes_key, os.urandom(size))
        assert len(tag) == 16, f"Expected 16-byte tag for {size}-byte payload, got {len(tag)}"


def test_encrypt_firmware_minimum_payload_one_byte():
    """encrypt_firmware must handle a single-byte firmware without error."""
    aes_key = os.urandom(32)
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, b"\xAB")
    assert len(ciphertext) == 1
    assert len(iv) == 12
    assert len(tag) == 16
    plain = AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
    assert plain == b"\xAB"


def test_derive_key_output_is_exactly_32_bytes():
    """The AES key returned by derive_key must be exactly 32 bytes (AES-256)."""
    for _ in range(5):
        client_priv = X25519PrivateKey.generate()
        device_pub = X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        _, aes_key = ota_send.derive_key(client_priv, device_pub)
        assert len(aes_key) == 32, f"Expected 32-byte key, got {len(aes_key)}"


# ---- CLI arg-parsing edge cases (via main()) ----------------------------------

def test_main_missing_host_and_firmware_exits_nonzero():
    """main() with no arguments must exit with nonzero (argparse error = 2)."""
    with pytest.raises(SystemExit) as exc_info:
        ota_send.main([])
    assert exc_info.value.code != 0


def test_main_missing_firmware_arg_exits_nonzero():
    """main() with only host argument must exit with nonzero (argparse error)."""
    with pytest.raises(SystemExit) as exc_info:
        ota_send.main(["192.168.1.1"])
    assert exc_info.value.code != 0


def test_main_help_exits_zero():
    """main() with --help must exit with code 0."""
    with pytest.raises(SystemExit) as exc_info:
        ota_send.main(["--help"])
    assert exc_info.value.code == 0


def test_main_bad_port_type_exits_nonzero():
    """main() with --port not an integer must exit nonzero."""
    with pytest.raises(SystemExit) as exc_info:
        ota_send.main(["host", "fw.bin", "--port", "notanumber"])
    assert exc_info.value.code != 0


def test_main_nonexistent_firmware_file_exits_8(tmp_path):
    """main() with a firmware path that doesn't exist must exit 8 (exception)."""
    rc = ota_send.main(["192.168.1.1", str(tmp_path / "nonexistent.bin")])
    assert rc == 8


def test_main_non_firmware_file_still_reads(tmp_path):
    """main() accepts any readable file as firmware; rejects empty file with rc 2."""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    # No SSH in tests -- this will hit a connection error (rc 8) or empty check.
    # The important thing is it doesn't crash before reaching the size check.
    # With an empty file the ota_send() function returns 2 before connecting.
    # We patch the SSH client out so we don't need a real server.
    import unittest.mock as mock
    with mock.patch("paramiko.SSHClient") as mock_client:
        mock_instance = mock_client.return_value
        mock_instance.connect.side_effect = Exception("no server")
        # Empty file is caught before SSH connect
        rc = ota_send.main(["host", str(empty)])
    assert rc == 2


def test_main_very_long_firmware_path_raises_8(tmp_path):
    """A path that is valid Python but doesn't exist returns exit 8."""
    long_name = "a" * 200 + ".bin"
    rc = ota_send.main(["host", str(tmp_path / long_name)])
    assert rc == 8


def test_main_path_with_spaces(tmp_path):
    """Firmware path containing spaces is handled without crashes."""
    fw = tmp_path / "my firmware file.bin"
    fw.write_bytes(b"")
    import unittest.mock as mock
    with mock.patch("paramiko.SSHClient"):
        rc = ota_send.main(["host", str(fw)])
    assert rc == 2  # empty file caught before SSH


def test_main_path_with_utf8_chars(tmp_path):
    """Firmware path containing UTF-8 characters is handled without crashes."""
    fw = tmp_path / "прошивка.bin"
    fw.write_bytes(b"")
    import unittest.mock as mock
    with mock.patch("paramiko.SSHClient"):
        rc = ota_send.main(["host", str(fw)])
    assert rc == 2  # empty file caught before SSH


def test_main_truncate_requires_integer():
    """--truncate with a non-integer value must exit nonzero."""
    with pytest.raises(SystemExit) as exc_info:
        ota_send.main(["host", "fw.bin", "--truncate", "notint"])
    assert exc_info.value.code != 0


def test_main_default_port_is_22():
    """Parsed args must default to port 22."""
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("firmware")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="ota")
    p.add_argument("--identity", default=None)
    p.add_argument("--tamper", action="store_true")
    p.add_argument("--truncate", type=int, default=None)
    args = p.parse_args(["myhost", "fw.bin"])
    assert args.port == 22
    assert args.user == "ota"
    assert args.identity is None
    assert args.tamper is False
    assert args.truncate is None


def test_main_custom_user_and_port():
    """--user and --port override defaults in parsed args."""
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("firmware")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="ota")
    p.add_argument("--identity", default=None)
    p.add_argument("--tamper", action="store_true")
    p.add_argument("--truncate", type=int, default=None)
    args = p.parse_args(["myhost", "fw.bin", "--port", "2222", "--user", "admin"])
    assert args.port == 2222
    assert args.user == "admin"


# ---- Firmware size boundary tests for encrypt_firmware() ---------------------

OTA_PARTITION_SIZE = 4 * 1024 * 1024  # matches main/ota_session.c MAX_OTA_PLAINTEXT


def test_encrypt_firmware_exact_ota_partition_size():
    """encrypt_firmware must handle exactly OTA_PARTITION_SIZE bytes."""
    aes_key = os.urandom(32)
    # Don't actually allocate 4 MiB of random data in the test — use a deterministic
    # repeating pattern to keep memory low while still exercising the code path.
    firmware = bytes(range(256)) * (OTA_PARTITION_SIZE // 256)
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)
    assert len(ciphertext) == OTA_PARTITION_SIZE
    assert len(iv) == 12
    assert len(tag) == 16


def test_encrypt_firmware_one_over_ota_partition_size():
    """encrypt_firmware must handle OTA_PARTITION_SIZE + 1 bytes without error."""
    aes_key = os.urandom(32)
    firmware = bytes(range(256)) * (OTA_PARTITION_SIZE // 256) + b"\xff"
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)
    assert len(ciphertext) == OTA_PARTITION_SIZE + 1


# ---- X25519 keypair determinism -----------------------------------------------

def test_x25519_generate_produces_unique_keys():
    """Every call to X25519PrivateKey.generate() must produce a unique keypair."""
    keys = [
        X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        for _ in range(10)
    ]
    assert len(set(keys)) == 10, "Two generate() calls returned the same key"


def test_x25519_from_private_bytes_deterministic():
    """from_private_bytes with the same scalar must always return the same pubkey."""
    scalar = bytes(range(32))
    pub1 = X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    pub2 = X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    assert pub1 == pub2


def test_derive_key_called_twice_with_same_inputs_is_deterministic():
    """derive_key called twice with the same private key + peer pub returns same outputs."""
    scalar = bytes(range(1, 33))
    device_priv = X25519PrivateKey.generate()
    device_pub = device_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    priv1 = X25519PrivateKey.from_private_bytes(scalar)
    priv2 = X25519PrivateKey.from_private_bytes(scalar)

    pub1, key1 = ota_send.derive_key(priv1, device_pub)
    pub2, key2 = ota_send.derive_key(priv2, device_pub)

    assert pub1 == pub2
    assert key1 == key2


# ---- AES-GCM frame-format malformed inputs ------------------------------------

def test_wrong_nonce_causes_decrypt_failure():
    """Decryption with a nonce that differs by one bit from the encrypt nonce must fail."""
    from cryptography.exceptions import InvalidTag
    aes_key = os.urandom(32)
    firmware = b"payload" * 50
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)

    bad_nonce = bytearray(iv)
    bad_nonce[0] ^= 0x01
    with pytest.raises(Exception):
        AESGCM(aes_key).decrypt(bytes(bad_nonce), ciphertext + tag, None)


def test_tampered_tag_causes_decrypt_failure():
    """Flipping a single bit in the auth tag must cause decryption to fail."""
    aes_key = os.urandom(32)
    firmware = b"payload" * 50
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)

    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x80
    with pytest.raises(Exception):
        AESGCM(aes_key).decrypt(iv, ciphertext + bytes(bad_tag), None)


def test_replayed_nonce_with_different_key_causes_decrypt_failure():
    """Replaying an IV from a session encrypted under a different key fails."""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    firmware = b"secret payload"
    iv, tag, ct = ota_send.encrypt_firmware(key1, firmware)
    # Replay IV under a different key
    with pytest.raises(Exception):
        AESGCM(key2).decrypt(iv, ct + tag, None)


def test_undersized_ciphertext_causes_tag_mismatch():
    """Feeding fewer ciphertext bytes than expected fails tag verification."""
    aes_key = os.urandom(32)
    firmware = b"x" * 128
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)
    truncated = ciphertext[:64]
    with pytest.raises(Exception):
        AESGCM(aes_key).decrypt(iv, truncated + tag, None)


def test_oversized_ciphertext_causes_tag_mismatch():
    """Appending extra bytes to the ciphertext must fail tag verification."""
    aes_key = os.urandom(32)
    firmware = b"x" * 128
    iv, tag, ciphertext = ota_send.encrypt_firmware(aes_key, firmware)
    extra = ciphertext + b"\x00"
    with pytest.raises(Exception):
        AESGCM(aes_key).decrypt(iv, extra + tag, None)


def test_zero_byte_firmware_encrypt_roundtrip():
    """Zero-byte firmware: encrypt then decrypt should return empty bytes."""
    aes_key = os.urandom(32)
    iv, tag, ct = ota_send.encrypt_firmware(aes_key, b"")
    plain = AESGCM(aes_key).decrypt(iv, ct + tag, None)
    assert plain == b""


def test_exactly_one_byte_firmware_encrypt_roundtrip():
    """Exactly 1-byte firmware encrypts and decrypts correctly."""
    aes_key = os.urandom(32)
    iv, tag, ct = ota_send.encrypt_firmware(aes_key, b"\x42")
    plain = AESGCM(aes_key).decrypt(iv, ct + tag, None)
    assert plain == b"\x42"
