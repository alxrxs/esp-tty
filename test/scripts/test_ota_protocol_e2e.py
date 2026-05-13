#!/usr/bin/env python3
"""
test/scripts/test_ota_protocol_e2e.py -- End-to-end OTA wire-protocol tests.

These exercise the full client/server protocol implemented by
scripts/ota_send.py's run_ota_protocol() against a fake "device" written in
pure Python.  No SSH layer is involved: the test feeds run_ota_protocol() a
pair of sendall/recv functions backed by an in-memory byte queue, while a
worker thread drives the device side using the cryptography library directly.

The fake device mirrors main/ota_session.c byte-for-byte:
  1. Generate ephemeral X25519 keypair, send [0x02][32B pub].
  2. Read 32B client pub.
  3. HKDF-SHA256(shared, salt=b"esp-tty-ota-v2", info=client_pub||device_pub).
  4. Read [4B LE len][12B IV][16B tag][len B ciphertext].
  5. AES-256-GCM decrypt; on success send 0x00, on failure 0xFF + reason + \\n.

Scenarios covered:
  * Happy path                  -> 0x00, exit 0
  * Tampered ciphertext         -> 0xFF "auth tag verify failed", exit 4
  * Truncated ciphertext        -> EOF mid-read; mapped to "truncated payload"
  * Oversize plaintext_len      -> device rejects "bad plaintext length"

Run with:
    venv/bin/pytest test/scripts/test_ota_protocol_e2e.py -v
"""

import os
import queue
import sys
import threading

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PROJECT_DIR, "scripts"))

import ota_send  # noqa: E402


HKDF_SALT = b"esp-tty-ota-v2"
MAX_OTA_PLAINTEXT = 4 * 1024 * 1024  # mirrors main/ota_session.c


# ---- Bidirectional byte pipe used to glue client and fake device together ----

class BytePipe:
    """
    One-direction byte stream backed by a thread-safe queue of chunks plus an
    EOF flag.  read_exact() blocks until N bytes arrive or the writer closes
    the pipe (in which case it raises IOError, just like _recv_exact).
    """
    def __init__(self):
        self._q = queue.Queue()
        self._buf = bytearray()
        self._closed = False
        self._lock = threading.Lock()

    def write(self, data):
        if not data:
            return
        self._q.put(bytes(data))

    def close(self):
        self._q.put(None)  # sentinel for EOF

    def read_exact(self, n):
        while len(self._buf) < n:
            chunk = self._q.get()
            if chunk is None:
                # EOF: signal short-read to caller
                raise IOError(
                    "pipe closed after %d/%d bytes" % (len(self._buf), n))
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


# ---- Fake device implementation ---------------------------------------------

class FakeDevice:
    """
    Implements the *device* half of the OTA protocol against a pair of
    BytePipes.  Runs on a background thread so the test's main thread can
    drive the client (run_ota_protocol).
    """
    def __init__(self, client_to_device, device_to_client):
        self.c2d = client_to_device  # client writes here, device reads
        self.d2c = device_to_client  # device writes here, client reads
        self.received_plaintext = None
        self.error = None
        self.failure_reason = None

    def _send_failure(self, reason):
        self.failure_reason = reason
        try:
            self.d2c.write(b"\xff")
            self.d2c.write(reason.encode("ascii"))
            self.d2c.write(b"\n")
        except Exception:
            pass

    def run(self):
        try:
            # 1. Generate device keypair, send [version][pub].
            dev_priv = X25519PrivateKey.generate()
            dev_pub = dev_priv.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)
            self.d2c.write(bytes([0x02]) + dev_pub)

            # 2. Read client pub.
            cli_pub = self.c2d.read_exact(32)
            cli_pub_obj = X25519PublicKey.from_public_bytes(cli_pub)

            # 3. Derive AES key.
            shared = dev_priv.exchange(cli_pub_obj)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=HKDF_SALT,
                info=cli_pub + dev_pub,
            ).derive(shared)

            # 4. Read header.
            len_buf = self.c2d.read_exact(4)
            plaintext_len = int.from_bytes(len_buf, "little")
            if plaintext_len == 0 or plaintext_len > MAX_OTA_PLAINTEXT:
                self._send_failure("bad plaintext length")
                return

            iv = self.c2d.read_exact(12)
            tag = self.c2d.read_exact(16)

            try:
                ciphertext = self.c2d.read_exact(plaintext_len)
            except IOError:
                self._send_failure("truncated payload")
                return

            # 5. AES-GCM verify+decrypt.
            try:
                plain = AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
            except Exception:
                self._send_failure("auth tag verify failed")
                return

            self.received_plaintext = plain
            self.d2c.write(b"\x00")
        except Exception as exc:  # pragma: no cover -- test-harness bug
            self.error = exc
            try:
                self._send_failure("device internal error")
            except Exception:
                pass
        finally:
            self.d2c.close()


# ---- Fixture: spin up a fake device, wire pipes to ota_send helpers ---------

def _spawn(firmware, *, tamper=False, truncate=None,
           override_plaintext_len=None):
    """
    Run run_ota_protocol() against a fresh FakeDevice on a background thread.

    Returns (exit_code, device).  `override_plaintext_len`, if set, monkey-
    patches the 4-byte length prefix to test the "oversize plaintext_len"
    rejection path -- we wrap sendall to rewrite the first 4 bytes that
    follow the client pubkey.
    """
    c2d = BytePipe()
    d2c = BytePipe()
    device = FakeDevice(c2d, d2c)

    t = threading.Thread(target=device.run, daemon=True)
    t.start()

    # The client only ever writes to c2d and only ever reads from d2c.
    # For the override_plaintext_len test we wrap sendall to splice in a
    # different length-prefix on the first 4-byte send that follows the
    # 32-byte client pubkey send.  This keeps the production code path
    # honest -- we are not poking at private helpers.
    state = {"client_pub_sent": False, "len_swapped": False}

    def sendall(data):
        if (override_plaintext_len is not None
                and state["client_pub_sent"]
                and not state["len_swapped"]
                and len(data) == 4):
            data = override_plaintext_len.to_bytes(4, "little")
            state["len_swapped"] = True
        c2d.write(data)
        if not state["client_pub_sent"] and len(data) == 32:
            state["client_pub_sent"] = True

    def recv_exact(n):
        return d2c.read_exact(n)

    def shutdown_write():
        c2d.close()

    # Silence the script's chatter from polluting test output.
    class _Sink:
        def write(self, _):
            pass

    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=firmware,
        tamper=tamper,
        truncate=truncate,
        shutdown_write_fn=shutdown_write,
        stderr=_Sink(),
        stdout=_Sink(),
    )

    # If we never truncated, close the upstream so the device thread can exit.
    try:
        c2d.close()
    except Exception:
        pass
    t.join(timeout=5.0)
    assert not t.is_alive(), "fake device thread did not exit"
    return rc, device


# ---- Tests ------------------------------------------------------------------

def test_e2e_happy_path():
    firmware = os.urandom(8192)
    rc, device = _spawn(firmware)
    assert rc == 0
    assert device.received_plaintext == firmware
    assert device.failure_reason is None


def test_e2e_small_firmware():
    firmware = b"esp-tty firmware payload!"  # tiny but nonzero
    rc, device = _spawn(firmware)
    assert rc == 0
    assert device.received_plaintext == firmware


def test_e2e_tampered_ciphertext_is_rejected():
    firmware = os.urandom(4096)
    rc, device = _spawn(firmware, tamper=True)
    # Device sends 0xFF "auth tag verify failed" -> ota_send returns 4.
    assert rc == 4
    assert device.failure_reason == "auth tag verify failed"
    assert device.received_plaintext is None


def test_e2e_truncated_payload_is_rejected():
    firmware = os.urandom(4096)
    # Announce full length, send only 100 bytes, then close.
    rc, device = _spawn(firmware, truncate=100)
    # Two possible outcomes depending on scheduling:
    #  - device sends "truncated payload" then EOF  -> rc == 4
    #  - device EOFs before any response byte        -> rc == 5
    # Both indicate the failure path triggered correctly.
    assert rc in (4, 5)
    assert device.received_plaintext is None
    if rc == 4:
        assert device.failure_reason == "truncated payload"


def test_e2e_oversize_plaintext_len_is_rejected():
    firmware = b"a" * 1024
    # Lie about the plaintext length: announce 8 MiB (above MAX_OTA_PLAINTEXT).
    rc, device = _spawn(firmware, override_plaintext_len=8 * 1024 * 1024)
    assert rc == 4
    assert device.failure_reason == "bad plaintext length"
    assert device.received_plaintext is None


def test_e2e_zero_plaintext_len_is_rejected():
    firmware = b"a" * 1024
    rc, device = _spawn(firmware, override_plaintext_len=0)
    assert rc == 4
    assert device.failure_reason == "bad plaintext length"
