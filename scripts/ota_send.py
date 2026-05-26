#!/usr/bin/env python3
"""
scripts/ota_send.py -- esp-tty OTA client (X25519 + AES-256-GCM)

Usage:
    ota_send.py <host> <firmware.bin> [--port 22] [--user ota]
                [--identity ~/.ssh/id_ed25519]
                [--tamper] [--truncate N]

Protocol (matches main/ota_session.c):

    Device  -> [0x02] [32B device_eph_x25519_pub]
    Client  -> [32B client_eph_x25519_pub]

    Both derive:
        shared = X25519(own_priv, peer_pub)
        key    = HKDF-SHA256(ikm=shared,
                             salt=b"esp-tty-ota-v2",
                             info=client_pub || device_pub,
                             length=32)

    Client  -> [4B plaintext_len LE] [12B IV] [16B tag] [N B ciphertext]
    Device  -> 0x00 (success, rebooting)
            or 0xFF + b"<reason>\\n" (failure)

Dependencies: paramiko, cryptography
"""

import argparse
import os
import secrets
import sys
from pathlib import Path

try:
    import paramiko
except ImportError:
    sys.stderr.write(
        "ota_send.py: missing 'paramiko'.  Install with:\n"
        "    .venv/bin/pip install -r requirements.txt\n"
    )
    sys.exit(2)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTO_VERSION = 0x02
X25519_LEN    = 32
IV_LEN        = 12
TAG_LEN       = 16
HKDF_SALT     = b"esp-tty-ota-v2"


def _recv_exact(chan, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = chan.recv(n - len(buf))
        if not chunk:
            raise IOError(
                "channel closed after %d/%d bytes" % (len(buf), n))
        buf.extend(chunk)
    return bytes(buf)


def _send_all(chan, data):
    view = memoryview(data)
    sent = 0
    while sent < len(view):
        n = chan.send(view[sent:])
        if n <= 0:
            raise IOError("channel send returned %d" % n)
        sent += n


# -----------------------------------------------------------------------------
# Pure-Python crypto helpers -- factored out so they can be unit-tested without
# any SSH/socket plumbing.  The CLI path below composes them; the test suite
# (test/scripts/test_ota_send_unit.py) exercises them directly.
# -----------------------------------------------------------------------------

def derive_key(client_priv, peer_pub_bytes):
    """
    Run the OTA handshake's key-agreement half on the *client* side.

    Returns (client_pub_bytes, aes_key) where:
        client_pub_bytes -- 32B raw X25519 public key to send to the device
        aes_key          -- 32B HKDF-SHA256(shared, salt, info=client||device)

    `client_priv` must be an X25519PrivateKey; `peer_pub_bytes` is the device's
    32-byte X25519 public key as received over the wire.
    """
    client_pub_bytes = client_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = client_priv.exchange(peer_pub)
    info = client_pub_bytes + peer_pub_bytes
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=info,
    ).derive(shared)
    return client_pub_bytes, aes_key


def encrypt_firmware(aes_key, firmware, *, iv=None):
    """
    AES-256-GCM encrypt `firmware` under `aes_key` with a random (or caller-
    supplied) 12-byte IV.

    Returns (iv, tag, ciphertext) -- separated for the wire format which
    transmits the tag before the ciphertext.
    """
    if iv is None:
        iv = secrets.token_bytes(IV_LEN)
    aesgcm = AESGCM(aes_key)
    # cryptography's AESGCM returns ciphertext||tag concatenated.
    ct_and_tag = aesgcm.encrypt(iv, firmware, None)
    ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]
    return iv, tag, ciphertext


def run_ota_protocol(sendall_fn, recv_exact_fn, firmware, *,
                     tamper=False, truncate=None,
                     shutdown_write_fn=None,
                     stderr=sys.stderr, stdout=sys.stdout,
                     read_failure_tail_fn=None):
    """
    Run the OTA wire protocol over an arbitrary byte stream.

    `sendall_fn(data)`        -- send all of `data`, raising on error
    `recv_exact_fn(n)`        -- return exactly `n` bytes, raising on EOF
    `shutdown_write_fn()`     -- optional, called after --truncate to half-close
    `read_failure_tail_fn()`  -- optional, returns bytes of best-effort error
                                 reason after a 0xFF byte; defaults to using
                                 recv_exact_fn one byte at a time until \\n

    Returns the numeric exit code (0 on success).
    """
    if not firmware:
        stderr.write("ota_send.py: firmware file is empty\n")
        return 2

    # ---- 1. Read device hello: [version][device_pub] ------------
    hello = recv_exact_fn(1 + X25519_LEN)
    if hello[0] != PROTO_VERSION:
        stderr.write(
            "ota_send.py: unsupported device protocol version 0x%02x\n"
            % hello[0])
        return 3
    device_pub_bytes = hello[1:]

    # ---- 2. Generate ephemeral keypair and send pub -------------
    client_priv = X25519PrivateKey.generate()
    client_pub_bytes, aes_key = derive_key(client_priv, device_pub_bytes)
    sendall_fn(client_pub_bytes)

    # ---- 3. Encrypt firmware ------------------------------------
    iv, tag, ciphertext = encrypt_firmware(aes_key, firmware)

    if tamper:
        ciphertext = bytearray(ciphertext)
        ciphertext[len(ciphertext) // 2] ^= 0x01
        ciphertext = bytes(ciphertext)
        stderr.write("ota_send.py: --tamper: flipped one byte of ciphertext\n")

    plaintext_len = len(firmware).to_bytes(4, "little")

    # ---- 4. Send header + body ----------------------------------
    sendall_fn(plaintext_len)
    sendall_fn(iv)
    sendall_fn(tag)

    if truncate is not None:
        stderr.write(
            "ota_send.py: --truncate %d: announcing %d but only sending %d\n"
            % (truncate, len(firmware), truncate))
        sendall_fn(ciphertext[:truncate])
        if shutdown_write_fn is not None:
            try:
                shutdown_write_fn()
            except Exception as exc:
                print(f"warn: shutdown_write failed: {exc}", file=sys.stderr)
    else:
        sendall_fn(ciphertext)

    # ---- 5. Read result -----------------------------------------
    try:
        result = recv_exact_fn(1)
    except IOError as exc:
        stderr.write("ota_send.py: no result byte from device: %s\n" % exc)
        return 5

    if result == b"\x00":
        stdout.write("ota_send.py: OTA accepted -- device is rebooting\n")
        return 0

    if result == b"\xff":
        if read_failure_tail_fn is not None:
            try:
                tail = read_failure_tail_fn()
            except Exception:
                tail = b""
        else:
            tail = bytearray()
            try:
                while len(tail) < 256:
                    b = recv_exact_fn(1)
                    if not b:
                        break
                    tail.extend(b)
                    if b == b"\n":
                        break
            except Exception:
                pass
            tail = bytes(tail)
        reason = bytes(tail).split(b"\n", 1)[0].decode("ascii", "replace")
        stderr.write("ota_send.py: device rejected OTA: %s\n" % reason)
        return 4

    stderr.write("ota_send.py: unexpected result byte 0x%02x\n" % result[0])
    return 6


def ota_send(host, firmware_path, *,
             port=22, user="ota", identity=None,
             tamper=False, truncate=None,
             known_hosts=None, timeout=30):

    firmware = Path(firmware_path).read_bytes()
    if not firmware:
        sys.stderr.write("ota_send.py: firmware file is empty\n")
        return 2
    print("ota_send.py: %s -> %s@%s:%d  (%d bytes)"
          % (firmware_path, user, host, port, len(firmware)))

    client = paramiko.SSHClient()
    # Reject unknown host keys by default to prevent MITM attacks.
    # Load system known_hosts for standard host fingerprints, then load
    # a caller-supplied file (--known-hosts) for device-specific entries.
    client.load_system_host_keys()
    if known_hosts:
        client.load_host_keys(os.path.expanduser(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    connect_kwargs = dict(hostname=host, port=port, username=user,
                          allow_agent=True, look_for_keys=True,
                          timeout=timeout)
    if identity:
        connect_kwargs["key_filename"] = os.path.expanduser(identity)

    client.connect(**connect_kwargs)
    try:
        transport = client.get_transport()
        chan = transport.open_session()
        # The device routes purely on username == "ota" and treats the
        # channel as a raw byte stream.  Use exec_command (no PTY) so
        # paramiko doesn't apply any LF/CRLF translation to the binary
        # payload.  The command string is unused on the device side.
        chan.exec_command("ota")

        def _tail():
            # Best-effort read of the failure reason line, with a short
            # timeout so we never hang forever waiting for the device to
            # close the channel.  Capped at 256 bytes total to prevent a
            # misbehaving server from streaming forever within the window.
            chan.settimeout(2.0)
            tail = bytearray()
            try:
                while len(tail) < 256:
                    b = chan.recv(64)
                    if not b:
                        break
                    tail.extend(b)
                    if b"\n" in tail:
                        break
            except Exception:
                pass
            return bytes(tail)

        return run_ota_protocol(
            sendall_fn=lambda d: _send_all(chan, d),
            recv_exact_fn=lambda n: _recv_exact(chan, n),
            firmware=firmware,
            tamper=tamper,
            truncate=truncate,
            shutdown_write_fn=chan.shutdown_write,
            read_failure_tail_fn=_tail,
        )

    finally:
        try:
            client.close()
        except Exception:
            pass


def main(argv):
    p = argparse.ArgumentParser(description="esp-tty OTA firmware sender")
    p.add_argument("host")
    p.add_argument("firmware")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="ota")
    p.add_argument("--identity", default=None,
                   help="path to SSH private key (optional; agent / "
                        "default key search is used otherwise)")
    p.add_argument("--known-hosts", default="~/.ssh/known_hosts",
                   help="path to known_hosts file for host key verification "
                        "(default: ~/.ssh/known_hosts)")
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH connection timeout in seconds (default: 30)")
    p.add_argument("--tamper", action="store_true",
                   help="(test) flip a single ciphertext byte before sending")
    p.add_argument("--truncate", type=int, default=None, metavar="N",
                   help="(test) only send N ciphertext bytes, then close")
    args = p.parse_args(argv)

    try:
        return ota_send(
            args.host, args.firmware,
            port=args.port, user=args.user, identity=args.identity,
            tamper=args.tamper, truncate=args.truncate,
            known_hosts=args.known_hosts, timeout=args.timeout,
        )
    except paramiko.AuthenticationException as exc:
        sys.stderr.write("ota_send.py: SSH auth failed: %s\n" % exc)
        return 7
    except Exception as exc:
        sys.stderr.write("ota_send.py: %s: %s\n" % (type(exc).__name__, exc))
        return 8


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
