#!/bin/sh
# test_mdns_build_matrix.sh -- build-flag matrix smoke test for mDNS
#
# Builds the firmware twice (MDNS_DISABLE defined vs. undefined) and checks
# that the expected symbols appear or are absent in each resulting ELF.
#
# Usage:
#   cd <project-root>
#   sh scripts/test_mdns_build_matrix.sh
#
# Requirements:
#   - PlatformIO with the esp32s3 environment configured
#   - main/config.h present (copy from config.h.example)
#   - nm or objdump available (binutils for xtensa or host nm for ELF grep)
#
# Exit codes:
#   0  both builds produced the expected symbol presence/absence
#   1  at least one check failed (or a build failed)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ELF_PATH="$PROJECT_DIR/.pio/build/esp32s3/firmware.elf"
CONFIG_H="$PROJECT_DIR/main/config.h"
MDNS_SENTINEL="/* mdns-matrix-test-disable */"

info()  { printf '[INFO]  %s\n' "$*"; }
ok()    { printf '[PASS]  %s\n' "$*"; }
fail()  { printf '[FAIL]  %s\n' "$*" >&2; exit 1; }

cleanup() {
    if grep -qF "$MDNS_SENTINEL" "$CONFIG_H" 2>/dev/null; then
        sed -i "/$MDNS_SENTINEL/d" "$CONFIG_H"
        info "config.h restored"
    fi
}
trap cleanup EXIT INT TERM

check_symbols() {
    local label="$1"
    local expect_present="$2"  # "yes" or "no"
    local elf="$3"

    if ! test -f "$elf"; then
        fail "ELF not found: $elf"
    fi

    for sym in mdns_init mdns_service_add; do
        if nm "$elf" 2>/dev/null | grep -q " $sym$" ||
           objdump -t "$elf" 2>/dev/null | grep -q " $sym$"; then
            found=yes
        else
            found=no
        fi

        if test "$expect_present" = "yes" && test "$found" = "no"; then
            fail "$label: expected symbol '$sym' to be present in ELF, but it was absent"
        fi
        if test "$expect_present" = "no" && test "$found" = "yes"; then
            fail "$label: expected symbol '$sym' to be absent from ELF, but it was present"
        fi
        ok "$label: symbol '$sym' presence=$found (expected $expect_present)"
    done
}

# ---- build 1: mDNS enabled (default -- MDNS_DISABLE not defined) ----------

info "Build 1/2: mDNS ENABLED (no MDNS_DISABLE in config.h)"
pio run -e esp32s3 -d "$PROJECT_DIR"
check_symbols "mDNS-enabled" yes "$ELF_PATH"

# ---- build 2: mDNS disabled (inject MDNS_DISABLE into config.h) -----------

info "Build 2/2: mDNS DISABLED (MDNS_DISABLE injected into config.h)"
printf '\n#define MDNS_DISABLE 1  %s\n' "$MDNS_SENTINEL" >> "$CONFIG_H"

pio run -e esp32s3 -d "$PROJECT_DIR"
check_symbols "mDNS-disabled" no "$ELF_PATH"

cleanup
info "Matrix test complete -- all symbol checks passed"
