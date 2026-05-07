#!/usr/bin/env python3
"""
test_qemu_boot.py — QEMU boot smoke test for esp-tty

Builds the wokwi firmware (BRIDGE_LOOPBACK mode), merges a flash image,
runs it under QEMU, and checks that the SSH server starts within the timeout.

Usage:
    python3 test/scripts/test_qemu_boot.py [--no-build] [--timeout 60]

Exit codes:
    0  SSH server started successfully
    1  Firmware failed to start or timed out
"""

import argparse
import subprocess
import sys
import os
import time
import re
import shutil

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PIO_BUILD   = os.path.join(PROJECT_DIR, ".pio", "build", "wokwi")

ESPTOOL     = os.path.join(os.path.expanduser("~"),
                           ".platformio", "packages",
                           "tool-esptoolpy", "esptool.py")
QEMU        = os.path.join(os.path.expanduser("~"),
                           ".espressif", "tools", "qemu-xtensa",
                           "esp_develop_9.2.2_20250817", "qemu", "bin",
                           "qemu-system-xtensa")

FLASH_IMG   = "/tmp/esp-tty-test-flash.bin"
FLASH_SIZE  = 16 * 1024 * 1024  # 16 MB

SUCCESS_PATTERN = re.compile(r"Listening on TCP port (\d+)")
FAILURE_PATTERNS = [
    re.compile(r"abort\(\) was called"),
    re.compile(r"Guru Meditation Error"),
    re.compile(r"ESP_ERROR_CHECK failed"),
]

# Required patterns that must appear before SUCCESS_PATTERN
# Note: NVS_KEYGEN uses an em-dash (U+2014) as in main.c
NVS_KEYGEN_PATTERN      = re.compile(r"NVS keys not found — generating new AES-XTS-256 key")
FINGERPRINT_PATTERN     = re.compile(r"Host key SHA-256 fingerprint: ([0-9a-f]{2}(?::[0-9a-f]{2}){31})")


def build_firmware():
    print("[test_qemu_boot] Building wokwi firmware …")
    result = subprocess.run(
        ["pio", "run", "-e", "wokwi"],
        cwd=PROJECT_DIR,
        capture_output=False,
    )
    if result.returncode != 0:
        print("[test_qemu_boot] FAIL: build failed")
        sys.exit(1)
    print("[test_qemu_boot] Build OK")


def merge_flash(flash_img=FLASH_IMG):
    print(f"[test_qemu_boot] Merging flash image → {flash_img} …")
    subprocess.run(
        [
            sys.executable, ESPTOOL,
            "--chip", "esp32s3",
            "merge_bin",
            "--flash_mode", "qio",
            "--flash_freq", "80m",
            "--flash_size", "16MB",
            "-o", flash_img,
            "0x0000",  os.path.join(PIO_BUILD, "bootloader.bin"),
            "0x8000",  os.path.join(PIO_BUILD, "partitions.bin"),
            "0x10000", os.path.join(PIO_BUILD, "firmware.bin"),
        ],
        cwd=PROJECT_DIR,
        check=True,
        capture_output=True,
    )
    # Pad to exactly 16 MB so QEMU's MTD driver is happy
    size = os.path.getsize(flash_img)
    if size < FLASH_SIZE:
        with open(flash_img, "ab") as f:
            f.write(b"\xff" * (FLASH_SIZE - size))
    print(f"[test_qemu_boot] Flash image: {os.path.getsize(flash_img) // 1024} KB")


def run_qemu(timeout_secs, flash_img=FLASH_IMG, label="test_qemu_boot"):
    """
    Run QEMU with the given flash image for up to timeout_secs.

    Returns a dict:
        {
          "success": bool,
          "port": str or None,
          "fingerprint": str or None,   # 95-char hex fingerprint if seen
          "nvs_keygen_seen": bool,
          "missing_patterns": list[str],  # names of required patterns not seen
        }
    """
    print(f"[{label}] Starting QEMU (timeout={timeout_secs}s) …")
    proc = subprocess.Popen(
        [
            QEMU,
            "-nographic",
            "-machine", "esp32s3",
            "-drive", f"file={flash_img},if=mtd,format=raw",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    deadline = time.time() + timeout_secs

    nvs_keygen_seen = False
    fingerprint     = None

    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.rstrip()
            print(f"  QEMU | {line}")

            # Track required patterns as we go
            if NVS_KEYGEN_PATTERN.search(line):
                nvs_keygen_seen = True

            m_fp = FINGERPRINT_PATTERN.search(line)
            if m_fp:
                fingerprint = m_fp.group(1)

            m = SUCCESS_PATTERN.search(line)
            if m:
                port = m.group(1)

                # Check all required patterns were seen
                missing = []
                if not nvs_keygen_seen:
                    missing.append("NVS keys not found — generating new AES-XTS-256 key")
                if fingerprint is None:
                    missing.append("Host key SHA-256 fingerprint: <32 hex pairs>")

                if missing:
                    for name in missing:
                        print(f"\n[{label}] FAIL — required pattern not seen: {name!r}")
                    proc.terminate()
                    return {
                        "success": False,
                        "port": port,
                        "fingerprint": fingerprint,
                        "nvs_keygen_seen": nvs_keygen_seen,
                        "missing_patterns": missing,
                    }

                print(f"\n[{label}] PASS — SSH server listening on port {port}")
                print(f"[{label}] Fingerprint: {fingerprint}")
                proc.terminate()
                return {
                    "success": True,
                    "port": port,
                    "fingerprint": fingerprint,
                    "nvs_keygen_seen": nvs_keygen_seen,
                    "missing_patterns": [],
                }

            for fp in FAILURE_PATTERNS:
                if fp.search(line):
                    print(f"\n[{label}] FAIL — crash detected: {line}")
                    proc.terminate()
                    return {
                        "success": False,
                        "port": None,
                        "fingerprint": fingerprint,
                        "nvs_keygen_seen": nvs_keygen_seen,
                        "missing_patterns": [],
                    }
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print(f"\n[{label}] FAIL — timed out waiting for SSH server")
    return {
        "success": False,
        "port": None,
        "fingerprint": fingerprint,
        "nvs_keygen_seen": nvs_keygen_seen,
        "missing_patterns": [],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-build", action="store_true",
                        help="Skip PlatformIO build (use existing binary)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Seconds to wait for SSH server startup")
    args = parser.parse_args()

    if not args.no_build:
        build_firmware()

    merge_flash()
    result = run_qemu(args.timeout)
    sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
