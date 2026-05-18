#!/usr/bin/env bash
# scripts/test_ssh_keepalive_build_matrix.sh
#
# Build-flag matrix test for SSH-protocol-level keepalive.
#
# Builds the firmware ELF under three SSH_KEEPALIVE_INTERVAL_SEC values:
#   1. default (30) -- keepalive enabled with default interval
#   2. 0            -- keepalive disabled; wolfSSH_global_request must be absent
#   3. 5            -- custom short interval
#
# Confirms:
#   - firmware ELF compiles cleanly under all three
#   - wolfSSH_global_request symbol is ABSENT from the ELF when interval=0
#
# Self-cleaning: removes temporary config.h patches on exit.
#
# Usage:
#   bash scripts/test_ssh_keepalive_build_matrix.sh
#
# Exits 0 on full pass, 1 on any failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_H="$PROJECT_DIR/main/config.h"
CONFIG_EXAMPLE="$PROJECT_DIR/main/config.example.h"
CONFIG_BACKUP="/tmp/esp-tty-ka-matrix-config.h.bak"
BUILD_DIR="$PROJECT_DIR/.pio/build/esp32s3"

cleanup() {
    if [ -f "$CONFIG_BACKUP" ]; then
        cp "$CONFIG_BACKUP" "$CONFIG_H"
        rm -f "$CONFIG_BACKUP"
    fi
}
trap cleanup EXIT

# Save original config.h if it exists
if [ -f "$CONFIG_H" ]; then
    cp "$CONFIG_H" "$CONFIG_BACKUP"
fi

# Generate a minimal config.h from the example (strip comments/blank lines,
# keep #define lines that have real values and are not already placeholders).
gen_base_config() {
    python3 - "$CONFIG_EXAMPLE" <<'PYEOF'
import sys, re
lines = open(sys.argv[1]).readlines()
out = []
for l in lines:
    s = l.strip()
    if s.startswith('#pragma once') or s.startswith('/*') or s.startswith('*') or not s:
        continue
    # Keep lines that look like complete macro definitions with real values
    if re.match(r'#define\s+\w+\s+\S', s):
        # Skip placeholder-only defines (contain "..." or "your-")
        if '...' in s or 'your-' in l.lower():
            continue
        out.append(l)
print(''.join(out))
PYEOF
}

PASS_COUNT=0
FAIL_COUNT=0

run_case() {
    local label="$1"
    local interval="$2"

    echo ""
    echo "=== Matrix case: $label (SSH_KEEPALIVE_INTERVAL_SEC=$interval) ==="

    # Build a minimal config.h with the required overrides
    {
        echo "#pragma once"
        echo "#define WIFI_SSID            \"test\""
        echo "#define WIFI_PASS            \"testpass\""
        echo "#define SSH_PORT             22"
        echo "#define AUTHORIZED_PUBKEYS   \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForBuildTestOnly test@test\""
        echo "#define OTA_AUTHORIZED_PUBKEY \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForBuildTestOnly test@test\""
        echo "#define USB_VID              0x303a"
        echo "#define USB_PID              0x4001"
        echo "#define USB_DEVICE_VERSION   0x0100"
        echo "#define USB_MANUFACTURER_STRING \"Test\""
        echo "#define USB_PRODUCT_STRING   \"Test\""
        echo "#define USB_SERIAL_STRING    \"SN-00000001\""
        echo "#define USB_CDC_STRING       \"Test CDC\""
        echo "#define DEVICE_HOSTNAME      \"esp-tty\""
        echo "#define WIFI_MAX_RETRY       0"
        echo "#define DHCP_RETRY_TIMEOUT_SEC 30"
        echo "#define MAX_TTY_KEYS         8"
        echo "#define SSH_HANDSHAKE_TIMEOUT_SEC 30"
        echo "#define TCP_KEEPALIVE_IDLE_SEC  60"
        echo "#define TCP_KEEPALIVE_INTVL_SEC 10"
        echo "#define TCP_KEEPALIVE_COUNT     3"
        echo "#define SSH_KEEPALIVE_INTERVAL_SEC $interval"
        echo "#define SSH_KEEPALIVE_COUNT_MAX    3"
        echo "#define OTA_ROLLBACK_DELAY_MS  30000"
        echo "#define RING_BUFFER_BYTES      (16 * 1024)"
        echo "#define SCROLLBACK_BUFFER_BYTES (128 * 1024)"
        echo "#define SCROLLBACK_REPLAY_LINES 1000"
    } > "$CONFIG_H"

    if ! pio run -e esp32s3 2>&1 | tail -5; then
        echo "FAIL: build failed for $label"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return
    fi

    local elf
    elf=$(find "$BUILD_DIR" -name "firmware.elf" | head -1)
    if [ -z "$elf" ]; then
        echo "FAIL: firmware.elf not found for $label"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return
    fi

    if [ "$interval" = "0" ]; then
        # wolfSSH_global_request must NOT appear in the binary when disabled
        if nm "$elf" 2>/dev/null | grep -q "wolfSSH_global_request"; then
            echo "FAIL: wolfSSH_global_request found in ELF but interval=0"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            return
        fi
        echo "OK: wolfSSH_global_request absent (interval=0)"
    else
        # wolfSSH_global_request MUST be present
        if ! nm "$elf" 2>/dev/null | grep -q "wolfSSH_global_request"; then
            echo "FAIL: wolfSSH_global_request missing from ELF (interval=$interval)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            return
        fi
        echo "OK: wolfSSH_global_request present (interval=$interval)"
    fi

    echo "PASS: $label"
    PASS_COUNT=$((PASS_COUNT + 1))
}

run_case "default-interval-30" "30"
run_case "disabled-interval-0" "0"
run_case "custom-interval-5"   "5"

echo ""
echo "=== Build matrix results ==="
echo "PASS: $PASS_COUNT / $((PASS_COUNT + FAIL_COUNT))"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
exit 0
