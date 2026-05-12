#!/usr/bin/env python3
"""
test_qemu_boot.py -- QEMU boot smoke test for esp-tty

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

PROJECT_DIR  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PIO_BUILD    = os.path.join(PROJECT_DIR, ".pio", "build", "wokwi")
TOOLCHAIN_BIN = os.path.join(os.path.expanduser("~"),
                              ".platformio", "packages",
                              "toolchain-xtensa-esp-elf", "bin")

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
NVS_KEYGEN_PATTERN      = re.compile(r"NVS keys not found -- generating new AES-XTS-256 key")
FINGERPRINT_PATTERN     = re.compile(r"Host key SHA-256 fingerprint: ([0-9a-f]{2}(?::[0-9a-f]{2}){31})")
TTY_KEYS_LOADED_PATTERN = re.compile(r"(\d+) TTY key\(s\) loaded")
PUMP_TEARDOWN_TIMEOUT_PATTERN = re.compile(r"did not exit within 5 s")


def build_firmware():
    print("[test_qemu_boot] Building wokwi firmware ...")
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
    print(f"[test_qemu_boot] Merging flash image -> {flash_img} ...")
    # Offsets must match partitions.csv:
    #   bootloader  0x0000
    #   partitions  0x8000
    #   otadata     0x10000  (2 KB OTA data -- marks ota_0 as active)
    #   ota_0       0x20000  (firmware binary)
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
            "0x10000", os.path.join(PIO_BUILD, "ota_data_initial.bin"),
            "0x20000", os.path.join(PIO_BUILD, "firmware.bin"),
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
    print(f"[{label}] Starting QEMU (timeout={timeout_secs}s) ...")
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
    boot_log        = ""

    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.rstrip()
            print(f"  QEMU | {line}")
            boot_log += line + "\n"

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
                    missing.append("NVS keys not found -- generating new AES-XTS-256 key")
                if fingerprint is None:
                    missing.append("Host key SHA-256 fingerprint: <32 hex pairs>")

                # TTY key load assertion: boot log must show at least one TTY
                # key loaded from AUTHORIZED_PUBKEYS (ssh_server.c logs
                # "N TTY key(s) loaded" after parsing the compile-time list).
                m_tty = TTY_KEYS_LOADED_PATTERN.search(boot_log)
                tty_key_count = int(m_tty.group(1)) if m_tty else 0
                assert tty_key_count >= 1, (
                    "Expected at least one TTY key to be loaded from "
                    "AUTHORIZED_PUBKEYS, but boot log shows 0 (or the "
                    "message is missing)."
                )

                # No teardown timeout assertion: a clean boot must never log
                # "teardown: pump_{ssh_to_usb,usb_to_ssh} did not exit within 5 s".
                # The smoke test doesn't normally trigger a teardown, but if a
                # future test boots a state that has TCP traffic mid-startup,
                # this catches pump-task deadlocks early.
                assert "did not exit within 5 s" not in boot_log, (
                    "Pump-task teardown timed out during boot -- indicates a "
                    "regression in the thread-safety of session teardown "
                    "(see commit 7b4f36d). This means the pump_done_sem "
                    "semaphore wasn't given by the pump tasks before the 5 s "
                    "deadline, suggesting wolfSSH state corruption or a "
                    "deadlock."
                )

                if missing:
                    for name in missing:
                        print(f"\n[{label}] FAIL -- required pattern not seen: {name!r}")
                    proc.terminate()
                    return {
                        "success": False,
                        "port": port,
                        "fingerprint": fingerprint,
                        "nvs_keygen_seen": nvs_keygen_seen,
                        "missing_patterns": missing,
                    }

                print(f"\n[{label}] PASS -- SSH server listening on port {port}")
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
                    print(f"\n[{label}] FAIL -- crash detected: {line}")
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

    print(f"\n[{label}] FAIL -- timed out waiting for SSH server")
    return {
        "success": False,
        "port": None,
        "fingerprint": fingerprint,
        "nvs_keygen_seen": nvs_keygen_seen,
        "missing_patterns": [],
    }


def check_elf_symbols(elf_path):
    """
    Post-build ELF symbol regression checks.

    1. AES-192 ABSENCE check: if any symbol matching aes.*192 or 192.*aes appears,
       it means wolfSSL AES-192 was compiled in despite NO_AES_192 being set.

    2. HW crypto PRESENCE check: esp_sha_try_hw_lock and wc_esp32AesEncrypt must
       both be present, proving wolfSSL is using hardware-accelerated crypto.

    Returns True on success, False (with print) on any failure.
    """
    nm_bin = os.path.join(TOOLCHAIN_BIN, "xtensa-esp32s3-elf-nm")
    if not os.path.isfile(nm_bin):
        # Fallback: search for any xtensa nm
        for name in ["xtensa-esp-elf-nm", "xtensa-esp32s3-elf-nm"]:
            candidate = os.path.join(TOOLCHAIN_BIN, name)
            if os.path.isfile(candidate):
                nm_bin = candidate
                break
        else:
            print(f"[check_elf_symbols] FAIL -- nm binary not found in {TOOLCHAIN_BIN}")
            return False

    print(f"[check_elf_symbols] Using nm: {nm_bin}")
    print(f"[check_elf_symbols] ELF: {elf_path}")

    try:
        nm_result = subprocess.run(
            [nm_bin, elf_path],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[check_elf_symbols] FAIL -- nm failed: {e}")
        return False

    nm_output = nm_result.stdout

    # -- Check 1: AES-192 must be ABSENT --------------------------------------
    # nm output format: "<addr> <type> <name>"
    # We check only the symbol NAME (third field), not the full line,
    # to avoid false positives from addresses that happen to contain "192".
    # Data symbols ('d'/'D') from mbedTLS cipher info tables are expected and
    # harmless -- they're static descriptors, not callable AES-192 code.
    # We flag only TEXT symbols ('t'/'T') named with aes*192 or 192*aes to
    # detect if wolfSSL has compiled in an AES-192 encryption function.
    aes192_matches = []
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        # nm output: addr type name  OR  type name (for undefined symbols)
        sym_name = parts[-1]   # symbol name is always last
        sym_type = parts[-2] if len(parts) >= 2 else ""
        # Flag AES-192 TEXT (code) symbols -- these indicate compiled-in AES-192 routines
        if re.search(r'(?i)(aes.*192|192.*aes)', sym_name) and sym_type.lower() in ('t',):
            aes192_matches.append(line)
    if aes192_matches:
        print("[check_elf_symbols] FAIL -- AES-192 code symbols found in ELF (NO_AES_192 regression):")
        for line in aes192_matches:
            print(f"  {line}")
        return False
    print("[check_elf_symbols] OK -- no AES-192 code symbols (NO_AES_192 is effective)")

    # -- Check 2: HW crypto symbols must be PRESENT ---------------------------
    required_hw_symbols = ["esp_sha_try_hw_lock", "wc_esp32AesEncrypt"]
    ok = True
    for sym in required_hw_symbols:
        if sym not in nm_output:
            print(f"[check_elf_symbols] FAIL -- HW crypto symbol missing: {sym!r}")
            print("  wolfSSL HW acceleration may have silently regressed to SW-only")
            ok = False
    if ok:
        print("[check_elf_symbols] OK -- HW crypto symbols present:", ", ".join(required_hw_symbols))

    return ok


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

    if not result["success"]:
        sys.exit(1)

    # Post-boot ELF symbol checks
    elf_path = os.path.join(PIO_BUILD, "firmware.elf")
    if not check_elf_symbols(elf_path):
        print("[test_qemu_boot] FAIL -- ELF symbol regression check failed")
        sys.exit(1)

    print("[test_qemu_boot] All checks passed")
    sys.exit(0)


if __name__ == "__main__":
    main()
