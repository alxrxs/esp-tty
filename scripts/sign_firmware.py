#!/usr/bin/env python3
"""
scripts/sign_firmware.py — Sign and encrypt an esp-tty OTA firmware image.

Produces a .ota file with the format:

  [magic  8B  "ESPOTA1\0"]
  [version 4B  LE uint32 = 1]
  [plaintext_len 4B  LE uint32]
  [aes_iv  12B  random]
  [aes_tag 16B  GCM authentication tag]
  [ciphertext NB  AES-256-GCM encrypted firmware]
  [signature 64B  ECDSA-P256 raw r||s over SHA-256(magic..end-of-ciphertext)]

The signature covers everything from the magic header through the last byte of
ciphertext (i.e., magic + version + plaintext_len + aes_iv + aes_tag + ciphertext).
The 64-byte signature itself is NOT included in the signed region.

Requires: Python ≥ 3.8, cryptography package (pip install cryptography)
  Falls back to subprocess openssl if the cryptography package is missing.

Usage:
  python3 scripts/sign_firmware.py <firmware.bin> [--out <output.ota>]
                                   [--key ota_keys/sign.key.pem]
                                   [--aes ota_keys/aes.key]
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys
import subprocess
import tempfile
from pathlib import Path

MAGIC = b"ESPOTA1\x00"   # 8 bytes
VERSION = 1

# ─── Crypto backend ──────────────────────────────────────────────────────────

def _load_cryptography():
    """Try to import the 'cryptography' package."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return True, ec, hashes, serialization, AESGCM
    except ImportError:
        return False, None, None, None, None


def aes_gcm_encrypt_native(key: bytes, iv: bytes, plaintext: bytes):
    """AES-256-GCM encrypt using cryptography package. Returns (ciphertext, tag)."""
    _ok, _ec, _hashes, _ser, AESGCM = _load_cryptography()
    gcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext+tag (tag is last 16 bytes)
    ct_and_tag = gcm.encrypt(iv, plaintext, None)
    return ct_and_tag[:-16], ct_and_tag[-16:]


def aes_gcm_encrypt_openssl(key: bytes, iv: bytes, plaintext: bytes):
    """AES-256-GCM encrypt via subprocess openssl (fallback)."""
    with tempfile.NamedTemporaryFile(delete=False) as f_in:
        f_in.write(plaintext)
        f_in_path = f_in.name
    f_out_path = f_in_path + ".enc"
    tag_path   = f_in_path + ".tag"
    try:
        subprocess.run([
            "openssl", "enc", "-aes-256-gcm",
            "-K", key.hex(), "-iv", iv.hex(),
            "-in",  f_in_path,
            "-out", f_out_path,
            "-e", "-nosalt",
        ], check=True, capture_output=True)
        # openssl enc for GCM doesn't output the tag cleanly; use Python struct approach
        raise RuntimeError("openssl enc does not support GCM tag extraction; install 'cryptography'")
    finally:
        os.unlink(f_in_path)
        if os.path.exists(f_out_path):
            os.unlink(f_out_path)


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    ok, *_ = _load_cryptography()
    if ok:
        return aes_gcm_encrypt_native(key, iv, plaintext)
    else:
        raise RuntimeError(
            "The 'cryptography' Python package is required for AES-GCM encryption.\n"
            "Install it with: pip install cryptography"
        )


def ecdsa_sign_native(key_pem: bytes, digest: bytes) -> bytes:
    """Sign digest with ECDSA-P256. Returns raw 64-byte r||s."""
    _ok, ec, hashes, serialization, _gcm = _load_cryptography()
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    privkey = serialization.load_pem_private_key(key_pem, password=None)
    # Sign the pre-computed digest directly using Prehashed
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    sig_der = privkey.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ecdsa_verify_native(pub_pem: bytes, digest: bytes, sig_rs: bytes) -> bool:
    """Verify raw 64-byte r||s signature. Returns True on success."""
    _ok, ec, hashes, serialization, _gcm = _load_cryptography()
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    pubkey = serialization.load_pem_public_key(pub_pem)
    r = int.from_bytes(sig_rs[:32], "big")
    s = int.from_bytes(sig_rs[32:], "big")
    sig_der = encode_dss_signature(r, s)
    try:
        pubkey.verify(sig_der, digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


# ─── Header construction ──────────────────────────────────────────────────────

def build_header(plaintext_len: int, iv: bytes, tag: bytes) -> bytes:
    """Return the 44-byte fixed header (magic + version + plaintext_len + iv + tag)."""
    return (
        MAGIC
        + struct.pack("<I", VERSION)
        + struct.pack("<I", plaintext_len)
        + iv
        + tag
    )

HEADER_SIZE = 8 + 4 + 4 + 12 + 16  # = 44 bytes


# ─── Main signing function ────────────────────────────────────────────────────

def sign_firmware(firmware_path: Path, key_path: Path, aes_path: Path, out_path: Path):
    plaintext = firmware_path.read_bytes()
    key_pem   = key_path.read_bytes()
    aes_key   = aes_path.read_bytes()

    if len(aes_key) != 32:
        sys.exit(f"ERROR: AES key must be exactly 32 bytes, got {len(aes_key)}")

    print(f"Plaintext size : {len(plaintext):,} bytes")

    # 1. Generate random 12-byte IV
    iv = os.urandom(12)

    # 2. AES-256-GCM encrypt
    ciphertext, tag = aes_gcm_encrypt(aes_key, iv, plaintext)
    print(f"Ciphertext size: {len(ciphertext):,} bytes")
    assert len(tag) == 16
    assert len(iv)  == 12

    # 3. Build header
    header = build_header(len(plaintext), iv, tag)
    assert len(header) == HEADER_SIZE

    # 4. SHA-256 over (header || ciphertext) — this is what we sign
    signed_region = header + ciphertext
    digest = hashlib.sha256(signed_region).digest()
    print(f"SHA-256(header||ct): {digest.hex()}")

    # 5. ECDSA-P256 sign the digest
    sig = ecdsa_sign_native(key_pem, digest)
    assert len(sig) == 64
    print(f"Signature (r||s, hex): {sig.hex()}")

    # 6. Assemble final image
    ota_image = signed_region + sig
    out_path.write_bytes(ota_image)
    print(f"OTA image written  : {out_path}  ({len(ota_image):,} bytes)")

    # 7. Self-test: verify our own output
    _self_test(out_path, key_path)

    return out_path


def _self_test(ota_path: Path, key_path: Path):
    """Parse and verify the just-written OTA image. Exits on failure."""
    data = ota_path.read_bytes()
    if len(data) < HEADER_SIZE + 64:
        sys.exit("SELF-TEST FAIL: image too short")

    magic       = data[:8]
    version     = struct.unpack_from("<I", data, 8)[0]
    pt_len      = struct.unpack_from("<I", data, 12)[0]
    iv          = data[16:28]
    tag         = data[28:44]
    ciphertext  = data[44:-64]
    sig         = data[-64:]

    if magic != MAGIC:
        sys.exit(f"SELF-TEST FAIL: bad magic {magic!r}")
    if version != VERSION:
        sys.exit(f"SELF-TEST FAIL: bad version {version}")

    signed_region = data[:-64]
    digest = hashlib.sha256(signed_region).digest()

    # Derive public key from private key for self-test
    ok, ec, hashes, serialization, _gcm = _load_cryptography()
    priv_pem = key_path.read_bytes()
    privkey = serialization.load_pem_private_key(priv_pem, password=None)
    pub_pem = privkey.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if not ecdsa_verify_native(pub_pem, digest, sig):
        sys.exit("SELF-TEST FAIL: ECDSA signature verification failed on our own output!")

    print(f"Self-test PASSED  : magic ok, version={version}, pt_len={pt_len}, sig ok")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Sign and encrypt an esp-tty OTA firmware image")
    p.add_argument("firmware",      type=Path, help="Input firmware.bin")
    p.add_argument("--out",  "-o",  type=Path, default=None,
                   help="Output path (default: <firmware>.ota)")
    p.add_argument("--key",  "-k",  type=Path, default=Path("ota_keys/sign.key.pem"),
                   help="ECDSA-P256 private key PEM (default: ota_keys/sign.key.pem)")
    p.add_argument("--aes",  "-a",  type=Path, default=Path("ota_keys/aes.key"),
                   help="AES-256 raw key file, 32 bytes (default: ota_keys/aes.key)")
    args = p.parse_args()

    firmware = args.firmware
    key_path = args.key
    aes_path = args.aes
    out_path = args.out or firmware.with_suffix(firmware.suffix + ".ota")

    for f, name in [(firmware, "firmware"), (key_path, "signing key"), (aes_path, "AES key")]:
        if not f.exists():
            sys.exit(f"ERROR: {name} file not found: {f}")

    sign_firmware(firmware, key_path, aes_path, out_path)


if __name__ == "__main__":
    main()
