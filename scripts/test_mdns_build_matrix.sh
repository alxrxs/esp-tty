#!/bin/sh
# test_mdns_build_matrix.sh -- build-flag matrix smoke test for mDNS
#
# mDNS is opt-in via MDNS_ENABLE in config.h.  This script builds the
# firmware twice (MDNS_ENABLE undefined vs. defined) and checks that the
# mDNS symbols are absent in the first build and present in the second.
#
# Usage:
#   cd <project-root>
#   sh scripts/test_mdns_build_matrix.sh
#
# Requirements:
#   - PlatformIO with the esp32s3 environment configured
#   - main/config.h present (copy from config.example.h)
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
MDNS_SENTINEL="/* mdns-matrix-test-enable */"

info()  { printf '[INFO]  %s\n' "$*"; }
ok()    { printf '[PASS]  %s\n' "$*"; }
fail()  { printf '[FAIL]  %s\n' "$*" >&2; exit 1; }

cleanup() {
    if grep -qF "$MDNS_SENTINEL" "$CONFIG_H" 2>/dev/null; then
        # The sentinel contains '/' (it's a C comment), so it can't be used
        # as a sed address delimiter.  Filter the line out with grep -vF
        # (fixed-string, sentinel-as-needle) into a temp file, then move it
        # back -- this restores config.h to exactly its pre-injection state.
        #
        # NOTE: grep -vF exits 1 when it emits NO lines (e.g. config.h held
        # only the injected line), so we must NOT chain `&&` off it -- that
        # would skip the mv and leave the sentinel in place.  Capture grep's
        # status explicitly and treat 0 (matches kept) and 1 (none kept) as
        # success; only a real error (>=2) aborts the restore.
        tmp="$(mktemp "${CONFIG_H}.XXXXXX")"
        # `set -e` would abort on grep's exit-1 (no lines kept), so capture
        # the status without letting it trip the errexit trap.
        grep_rc=0
        grep -vF "$MDNS_SENTINEL" "$CONFIG_H" > "$tmp" || grep_rc=$?
        if [ "$grep_rc" -le 1 ]; then
            mv "$tmp" "$CONFIG_H"
            info "config.h restored"
        else
            rm -f "$tmp"
            fail "cleanup: grep failed (rc=$grep_rc) restoring $CONFIG_H"
        fi
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

# ---- build 1: mDNS off (default -- MDNS_ENABLE undefined) -----------------

info "Build 1/2: mDNS OFF (MDNS_ENABLE undefined in config.h)"
pio run -e esp32s3 -d "$PROJECT_DIR"
check_symbols "mDNS-off" no "$ELF_PATH"

# ---- build 2: mDNS on (inject MDNS_ENABLE into config.h) ------------------

info "Build 2/2: mDNS ON (MDNS_ENABLE injected into config.h)"
# Inject exactly one sentinel-tagged line so cleanup (grep -vF on the
# sentinel) restores config.h byte-for-byte.  No leading blank line: a
# blank line carries no sentinel and would survive the grep filter.
# Guard against a config.h without a trailing newline (the append would
# otherwise splice onto the last existing line) by adding a separator \n
# only in that case.
if [ -s "$CONFIG_H" ] && [ "$(tail -c1 "$CONFIG_H")" != "" ]; then
    printf '\n' >> "$CONFIG_H"
fi
printf '#define MDNS_ENABLE 1  %s\n' "$MDNS_SENTINEL" >> "$CONFIG_H"

pio run -e esp32s3 -d "$PROJECT_DIR"
check_symbols "mDNS-on" yes "$ELF_PATH"

cleanup
info "Matrix test complete -- all symbol checks passed"
