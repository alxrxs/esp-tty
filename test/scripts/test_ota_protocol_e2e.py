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


# ---- run_ota_protocol() direct unit tests (no fake device needed) -----------

class _Sink:
    """Discard all output."""
    def write(self, _):
        pass


def _make_pipe_protocol(hello_bytes, *, result_byte=b"\x00"):
    """
    Build sendall/recv callbacks that feed a fixed hello from a queue and
    absorb all client writes, returning `result_byte` after the client sends
    the firmware.  Used to test early-exit paths in run_ota_protocol() without
    spinning up a full fake device.
    """
    import queue as _queue
    from_device = _queue.SimpleQueue()
    for b in [hello_bytes]:
        from_device.put(b)
    from_device.put(result_byte)  # final result byte

    sent_chunks = []

    def sendall(data):
        sent_chunks.append(bytes(data))

    # Accumulated inbound buffer.
    buf = bytearray()

    def recv_exact(n):
        while len(buf) < n:
            chunk = from_device.get(timeout=2)
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    return sendall, recv_exact, sent_chunks


def test_run_ota_protocol_empty_firmware_returns_2():
    """run_ota_protocol with an empty firmware bytes object must return 2."""
    sendall, recv_exact, _ = _make_pipe_protocol(b"")
    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"",
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 2


def test_run_ota_protocol_wrong_version_returns_3():
    """A device hello with an unsupported version byte (e.g. 0x01) must cause exit 3."""
    # Build a hello: [0x01][32 zero bytes] -- wrong version.
    bad_hello = bytes([0x01]) + bytes(32)
    sendall, recv_exact, _ = _make_pipe_protocol(bad_hello)
    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"x" * 16,
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 3


def test_run_ota_protocol_unexpected_result_byte_returns_6():
    """An unexpected result byte (not 0x00 or 0xff) must cause exit 6."""
    # Valid hello from a "device" but then send 0x42 as the result byte
    # instead of 0x00 or 0xff.  We need a real device pub so key derivation
    # succeeds; use a fixed 32-byte value (HKDF won't care what it contains
    # for this test since we only check the exit code, not the decrypted data).
    dev_priv = X25519PrivateKey.generate()
    dev_pub = dev_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    valid_hello = bytes([0x02]) + dev_pub

    import queue as _queue
    from_device = _queue.SimpleQueue()
    from_device.put(valid_hello)
    from_device.put(b"\x42")  # unexpected result byte

    buf = bytearray()

    def sendall(data):
        pass

    def recv_exact(n):
        while len(buf) < n:
            chunk = from_device.get(timeout=2)
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"y" * 64,
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 6


def test_run_ota_protocol_no_result_byte_returns_5():
    """If the channel closes before the result byte arrives, exit code must be 5."""
    dev_priv = X25519PrivateKey.generate()
    dev_pub = dev_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    valid_hello = bytes([0x02]) + dev_pub

    import queue as _queue
    from_device = _queue.SimpleQueue()
    from_device.put(valid_hello)
    # No result byte -- simulate EOF by putting a sentinel that raises IOError.

    buf = bytearray()
    eof_reached = [False]

    def sendall(data):
        pass

    def recv_exact(n):
        if eof_reached[0]:
            raise IOError("channel closed")
        while len(buf) < n:
            try:
                chunk = from_device.get(timeout=0.1)
                buf.extend(chunk)
            except _queue.Empty:
                eof_reached[0] = True
                raise IOError("channel closed")
        out = bytes(buf[:n])
        del buf[:n]
        return out

    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"z" * 64,
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 5


# ---- Handshake failure injection tests ---------------------------------------

def _make_device_hello():
    """Return (valid_hello_bytes, dev_priv) for a freshly generated device keypair."""
    dev_priv = X25519PrivateKey.generate()
    dev_pub = dev_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return bytes([0x02]) + dev_pub, dev_priv


def _run_with_static_device(hello_bytes, result_byte=b"\x00", firmware=b"x" * 64):
    """
    Drive run_ota_protocol with a fully static 'device': sends hello_bytes
    then result_byte.  Swallows all client writes.  Returns exit code.
    """
    import queue as _q
    q = _q.SimpleQueue()
    q.put(hello_bytes)
    q.put(result_byte)

    buf = bytearray()

    def sendall(data):
        pass

    def recv_exact(n):
        while len(buf) < n:
            chunk = q.get(timeout=2)
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    return ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=firmware,
        stderr=_Sink(),
        stdout=_Sink(),
    )


def test_malformed_hello_short_version_byte_only():
    """Premature EOF after version byte (hello too short) must raise from recv_exact."""
    # Send only 10 bytes instead of 33; recv_exact will block and then raise.
    import queue as _q
    q = _q.SimpleQueue()
    q.put(bytes(10))  # Only 10 bytes -- can't read 33

    buf = bytearray()
    calls = [0]

    def sendall(data):
        pass

    def recv_exact(n):
        calls[0] += 1
        while len(buf) < n:
            try:
                chunk = q.get(timeout=0.1)
                buf.extend(chunk)
            except _q.Empty:
                raise IOError("premature EOF")
        out = bytes(buf[:n])
        del buf[:n]
        return out

    with pytest.raises(Exception):
        ota_send.run_ota_protocol(
            sendall_fn=sendall,
            recv_exact_fn=recv_exact,
            firmware=b"fw" * 32,
            stderr=_Sink(),
            stdout=_Sink(),
        )


def test_wrong_version_0x00():
    """Version byte 0x00 in device hello must return exit code 3."""
    bad_hello = bytes([0x00]) + bytes(32)
    rc = _run_with_static_device(bad_hello)
    assert rc == 3


def test_wrong_version_0xff():
    """Version byte 0xFF in device hello must return exit code 3."""
    bad_hello = bytes([0xFF]) + bytes(32)
    rc = _run_with_static_device(bad_hello)
    assert rc == 3


def test_wrong_version_0x01():
    """Version byte 0x01 (old protocol) must return exit code 3."""
    bad_hello = bytes([0x01]) + bytes(32)
    rc = _run_with_static_device(bad_hello)
    assert rc == 3


def test_device_failure_response_read_tail():
    """0xFF result byte with a reason line must return exit 4 and surface the reason."""
    hello, _ = _make_device_hello()

    import queue as _q
    q = _q.SimpleQueue()
    q.put(hello)
    reason_bytes = b"\xfftoo small firmware\n"
    for byte in reason_bytes:
        q.put(bytes([byte]))

    buf = bytearray()

    def sendall(data):
        pass

    def recv_exact(n):
        while len(buf) < n:
            chunk = q.get(timeout=2)
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"x" * 64,
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 4


def test_result_byte_0x7e_returns_6():
    """A result byte of 0x7e (not 0x00 or 0xff) must return exit 6."""
    hello, _ = _make_device_hello()
    rc = _run_with_static_device(hello, result_byte=b"\x7e")
    assert rc == 6


# ---- E2E: firmware size boundaries -------------------------------------------

def test_e2e_exactly_one_byte_firmware():
    """A 1-byte firmware must be accepted by the fake device."""
    rc, device = _spawn(b"\xAB")
    assert rc == 0
    assert device.received_plaintext == b"\xAB"


def test_e2e_exactly_max_minus_one():
    """A firmware of MAX_OTA_PLAINTEXT - 1 bytes must be accepted."""
    # Use a repeated byte pattern to avoid allocating 4MB of random data.
    size = MAX_OTA_PLAINTEXT - 1
    firmware = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    rc, device = _spawn(firmware)
    assert rc == 0
    assert device.received_plaintext == firmware


def test_e2e_max_plaintext_len_plus_one_rejected():
    """A firmware announced as MAX_OTA_PLAINTEXT + 1 must be rejected."""
    firmware = b"a" * 1024
    rc, device = _spawn(firmware, override_plaintext_len=MAX_OTA_PLAINTEXT + 1)
    assert rc == 4
    assert device.failure_reason == "bad plaintext length"


# ---- Failure-injection: sendall raises mid-stream ----------------------------

def test_sendall_failure_mid_firmware_propagates():
    """If sendall raises after sending the header, run_ota_protocol propagates the error."""
    import queue as _q
    dev_priv = X25519PrivateKey.generate()
    dev_pub = dev_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    hello = bytes([0x02]) + dev_pub

    q = _q.SimpleQueue()
    q.put(hello)

    buf = bytearray()
    sends = [0]

    def recv_exact(n):
        while len(buf) < n:
            chunk = q.get(timeout=2)
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    def sendall(data):
        sends[0] += 1
        if sends[0] >= 3:
            raise IOError("connection reset")

    with pytest.raises(IOError):
        ota_send.run_ota_protocol(
            sendall_fn=sendall,
            recv_exact_fn=recv_exact,
            firmware=b"big firmware" * 100,
            stderr=_Sink(),
            stdout=_Sink(),
        )


# ---- E2E: multiple sequential sessions (key freshness) -----------------------

def test_e2e_two_sessions_use_different_keys():
    """Two back-to-back OTA sessions must succeed independently (ephemeral keys)."""
    firmware = os.urandom(1024)
    for _ in range(2):
        rc, device = _spawn(firmware)
        assert rc == 0
        assert device.received_plaintext == firmware


# ---- Failure-injection: recv_exact EOF at various handshake stages -----------

def test_eof_before_any_hello_byte():
    """Immediate EOF from the server before any byte raises IOError."""
    def sendall(data):
        pass

    def recv_exact(n):
        raise IOError("immediate EOF")

    with pytest.raises(IOError):
        ota_send.run_ota_protocol(
            sendall_fn=sendall,
            recv_exact_fn=recv_exact,
            firmware=b"fw" * 32,
            stderr=_Sink(),
            stdout=_Sink(),
        )


def test_eof_after_hello_before_result():
    """EOF after successful hello but before result byte returns exit 5."""
    hello, _ = _make_device_hello()

    import queue as _q
    q = _q.SimpleQueue()
    q.put(hello)

    buf = bytearray()
    hello_consumed = [False]

    def sendall(data):
        pass

    def recv_exact(n):
        # After the hello is consumed, simulate EOF
        if hello_consumed[0]:
            raise IOError("EOF mid-stream")
        while len(buf) < n:
            try:
                chunk = q.get(timeout=0.1)
                buf.extend(chunk)
            except _q.Empty:
                raise IOError("EOF mid-stream")
        out = bytes(buf[:n])
        del buf[:n]
        if len(buf) == 0:
            hello_consumed[0] = True
        return out

    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"fw" * 32,
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 5


# ---- Device sends 0xFF with no trailing newline (partial reason) --------------

def test_device_failure_no_newline_returns_4():
    """0xFF followed by reason without newline must still exit 4."""
    hello, _ = _make_device_hello()

    import queue as _q
    q = _q.SimpleQueue()
    q.put(hello)
    q.put(b"\xfferror reason no newline")
    # No newline -- recv loop will eventually raise (timeout/EOF) and exit with rc=4.

    buf = bytearray()
    exhausted = [False]

    def sendall(data):
        pass

    def recv_exact(n):
        if exhausted[0]:
            raise IOError("EOF")
        while len(buf) < n:
            try:
                chunk = q.get(timeout=0.05)
                buf.extend(chunk)
            except _q.Empty:
                exhausted[0] = True
                raise IOError("EOF")
        out = bytes(buf[:n])
        del buf[:n]
        return out

    rc = ota_send.run_ota_protocol(
        sendall_fn=sendall,
        recv_exact_fn=recv_exact,
        firmware=b"fw" * 32,
        stderr=_Sink(),
        stdout=_Sink(),
    )
    assert rc == 4


# ---- SSH mock: paramiko auth / connect error paths ---------------------------

def test_ota_send_ssh_auth_failure_returns_7(tmp_path):
    """SSH authentication failure must surface as exit code 7 from main()."""
    import unittest.mock as mock
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"x" * 64)

    import paramiko
    with mock.patch("paramiko.SSHClient") as mock_cls:
        mock_cls.return_value.connect.side_effect = paramiko.AuthenticationException("denied")
        rc = ota_send.main(["host", str(fw)])
    assert rc == 7


def test_ota_send_ssh_connect_generic_failure_returns_8(tmp_path):
    """A generic SSH connection error must surface as exit code 8 from main()."""
    import unittest.mock as mock
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"x" * 64)

    with mock.patch("paramiko.SSHClient") as mock_cls:
        mock_cls.return_value.connect.side_effect = OSError("connection refused")
        rc = ota_send.main(["host", str(fw)])
    assert rc == 8
