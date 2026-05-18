#!/bin/sh
# test_ntp_build_matrix.sh -- build-flag matrix test for NTP_ENABLE
#
# What it does
# ------------
# 1. Builds the firmware TWICE from a temporary config.h:
#      Case A: NTP_ENABLE undefined  (default, off-grid-safe)
#      Case B: NTP_ENABLE defined    (SNTP client active)
# 2. Checks the resulting ELF for the presence / absence of the
#    esp_netif_sntp_init symbol:
#      Case A: symbol must NOT appear  (feature compiled out)
#      Case B: symbol MUST appear      (feature compiled in)
# 3. Prints PASS or FAIL for each case and exits non-zero on any failure.
#
# Dependencies
# ------------
#   - pio (PlatformIO CLI) in PATH or .venv/bin/pio
#   - xtensa-esp32s3-elf-nm (part of the ESP-IDF toolchain)
#   - A minimal config.example.h-compatible config.h (the script writes one)
#
# Usage
#   scripts/test_ntp_build_matrix.sh
#
# The script is self-cleaning: it restores main/config.h to its prior state
# (or removes it if it did not exist) on exit, and removes the temporary ELF
# copy.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(cd "$SCRIPT_DIR/.." && pwd)"

PIO="$(
  test -x "$PROJ/.venv/bin/pio" && echo "$PROJ/.venv/bin/pio" ||
  test -x "$PROJ/venv/bin/pio"  && echo "$PROJ/venv/bin/pio"  ||
  echo pio
)"

CONFIG_H="$PROJ/main/config.h"
CONFIG_H_BAK="$PROJ/main/config.h.matrix.bak"
TMP_ELF_A="$PROJ/.pio/build/matrix_test_no_ntp.elf"
TMP_ELF_B="$PROJ/.pio/build/matrix_test_ntp.elf"

# Try to locate nm for the xtensa toolchain.
NM="$(command -v xtensa-esp32s3-elf-nm 2>/dev/null || true)"
if [ -z "$NM" ]; then
    # PlatformIO installs it under ~/.platformio/packages/toolchain-xtensa-esp-elf/bin/
    NM="$(find "$HOME/.platformio/packages" -name "xtensa-esp32s3-elf-nm" 2>/dev/null | head -1 || true)"
fi
if [ -z "$NM" ]; then
    echo "ERROR: xtensa-esp32s3-elf-nm not found -- install the ESP-IDF toolchain" >&2
    exit 1
fi

# Locate the built ELF (path varies slightly with PlatformIO version).
find_elf() {
    find "$PROJ/.pio/build/esp32s3" -name "firmware.elf" 2>/dev/null | head -1
}

PASS=0
FAIL=0

run_case() {
    label="$1"      # e.g. "A (NTP_ENABLE off)"
    ntp_define="$2" # "0" or "1"
    dst_elf="$3"

    echo ""
    echo "=== Case $label ==="

    # Write a minimal config.h for this case.
    cat > "$CONFIG_H" << 'EOF_COMMON'
#pragma once
#define WIFI_SSID   "matrix-test"
#define WIFI_PASS   "matrix-test"
#define SSH_PORT    22
#define AUTHORIZED_PUBKEYS \
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBuildMatrixTestKey matrix-test"
#define OTA_AUTHORIZED_PUBKEY "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBuildMatrixTestKey matrix-test"
EOF_COMMON

    if [ "$ntp_define" = "1" ]; then
        printf '#define NTP_ENABLE\n#define NTP_SERVERS "pool.ntp.org"\n' >> "$CONFIG_H"
    fi

    # Clean prior build artefacts to force a relink.
    rm -f "$PROJ/.pio/build/esp32s3/firmware.elf"

    if ! "$PIO" run -e esp32s3 -d "$PROJ" 2>&1; then
        echo "FAIL: build failed for case $label"
        FAIL=$((FAIL + 1))
        return
    fi

    ELF="$(find_elf)"
    if [ -z "$ELF" ]; then
        echo "FAIL: ELF not found after build for case $label"
        FAIL=$((FAIL + 1))
        return
    fi

    cp "$ELF" "$dst_elf"

    has_symbol=0
    if "$NM" "$dst_elf" 2>/dev/null | grep -q "esp_netif_sntp_init"; then
        has_symbol=1
    fi

    if [ "$ntp_define" = "0" ] && [ "$has_symbol" = "0" ]; then
        echo "PASS: esp_netif_sntp_init absent when NTP_ENABLE is not defined"
        PASS=$((PASS + 1))
    elif [ "$ntp_define" = "0" ] && [ "$has_symbol" = "1" ]; then
        echo "FAIL: esp_netif_sntp_init present even though NTP_ENABLE is not defined"
        FAIL=$((FAIL + 1))
    elif [ "$ntp_define" = "1" ] && [ "$has_symbol" = "1" ]; then
        echo "PASS: esp_netif_sntp_init present when NTP_ENABLE is defined"
        PASS=$((PASS + 1))
    else
        echo "FAIL: esp_netif_sntp_init absent even though NTP_ENABLE is defined"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    # Restore config.h to its prior state.
    if [ -f "$CONFIG_H_BAK" ]; then
        mv "$CONFIG_H_BAK" "$CONFIG_H"
    else
        rm -f "$CONFIG_H"
    fi
    rm -f "$TMP_ELF_A" "$TMP_ELF_B"
}
trap cleanup EXIT INT TERM

# Back up any existing config.h.
if [ -f "$CONFIG_H" ]; then
    cp "$CONFIG_H" "$CONFIG_H_BAK"
fi

run_case "A (NTP_ENABLE off)" 0 "$TMP_ELF_A"
run_case "B (NTP_ENABLE on)"  1 "$TMP_ELF_B"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

[ "$FAIL" = "0" ]
