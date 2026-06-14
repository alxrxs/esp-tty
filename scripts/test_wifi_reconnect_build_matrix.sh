#!/bin/sh
# test_wifi_reconnect_build_matrix.sh -- build-flag matrix guarding the Wi-Fi
# reconnect / cert-rotation symbols (audit findings W1 + W2).
#
# Background
# ----------
#   W1  wifi_init_sta() used to unregister the WIFI_EVENT/ESP_EVENT_ANY_ID
#       handler right after the first connect, so the non-smart Mode A/B paths
#       never saw WIFI_EVENT_STA_DISCONNECTED again and could not reconnect.
#       The fix keeps that handler registered for the life of the session.
#       wifi_init_sta() is a public API function compiled in every non-loopback
#       build, so the ordinary `make build` already type-checks the fix; this
#       script's value for W1 is keeping it building under the NTP matrix below.
#
#   W2  s_eap_creds_just_rotated, wifi_signal_eap_creds_rotated() and
#       s_self_teardown_expected were declared INSIDE
#       `#if !defined(BRIDGE_LOOPBACK) && defined(NTP_ENABLE)` but are
#       referenced UNCONDITIONALLY by the disconnect handler (and
#       wifi_signal_eap_creds_rotated() is also called from cert_renewer.c), so
#       any build with NTP_ENABLE undefined failed to compile/link. The fix
#       moves the three symbols to unconditional file scope. THIS is the
#       primary regression guarded here.
#
# What this script asserts
# ------------------------
# It builds esp32s3_zero from a config derived from the complete, known-good
# main/config.big.h, in two cases, and checks the build SUCCEEDS and the W2
# symbol is compiled into wifi.c.o (object file, not the gc-sections'd ELF):
#
#   Case 1  config.big.h as-is (NTP_ENABLE on)          -> baseline, MUST build
#   Case 2  config.big.h + #undef NTP_ENABLE/NTP_BEFORE_EAPTLS (NTP off)
#                                                        -> the W2 regression;
#                                                           MUST build
#
# Deriving from config.big.h (via #include) rather than a hand-rolled minimal
# config means we can't silently miss a required macro (USB_*, DEVICE_HOSTNAME,
# SSH_PORT, ...): if config.big.h builds, the only variable under test is NTP.
#
# SAFETY: main/config.h is normally a SYMLINK to a per-device config. This
# script NEVER writes through that symlink (an earlier version did `cat > config.h`
# and clobbered the symlink *target*, destroying the device config). It removes
# config.h first, writes a plain wrapper file, and a trap restores the original
# symlink/file/absent state on every exit path.
#
# Dependencies: pio (or .venv/bin/pio), xtensa-esp32s3-elf-nm.
# Usage: scripts/test_wifi_reconnect_build_matrix.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(cd "$SCRIPT_DIR/.." && pwd)"

PIO="$(
  test -x "$PROJ/.venv/bin/pio" && echo "$PROJ/.venv/bin/pio" ||
  test -x "$PROJ/venv/bin/pio"  && echo "$PROJ/venv/bin/pio"  ||
  echo pio
)"

CONFIG_H="$PROJ/main/config.h"
CONFIG_H_BAK="$PROJ/main/config.h.reconnect_matrix.bak"
BASE_CONFIG="config.big.h"   # complete, known-good config we derive from
ENV="esp32s3_zero"

# Bail out early if the base config is missing (e.g. fresh clone).
if [ ! -f "$PROJ/main/$BASE_CONFIG" ]; then
    echo "SKIP: main/$BASE_CONFIG not present -- cannot run the matrix." >&2
    exit 0
fi

# Locate nm for the xtensa toolchain (optional symbol check).
NM="$(command -v xtensa-esp32s3-elf-nm 2>/dev/null || true)"
[ -n "$NM" ] || NM="$(find "$HOME/.platformio/packages" -name xtensa-esp32s3-elf-nm 2>/dev/null | head -1 || true)"

# --- capture original config.h state so we can restore it EXACTLY ---
ORIG_KIND="absent"; ORIG_LINK=""
if [ -L "$CONFIG_H" ]; then
    ORIG_KIND="symlink"; ORIG_LINK="$(readlink "$CONFIG_H")"
elif [ -f "$CONFIG_H" ]; then
    ORIG_KIND="file"; cp "$CONFIG_H" "$CONFIG_H_BAK"
fi

restore() {
    rm -f "$CONFIG_H"
    case "$ORIG_KIND" in
        symlink) ln -sfn "$ORIG_LINK" "$CONFIG_H" ;;
        file)    [ -f "$CONFIG_H_BAK" ] && mv "$CONFIG_H_BAK" "$CONFIG_H" ;;
        absent)  : ;;
    esac
}
trap restore EXIT INT TERM

find_elf() { find "$PROJ/.pio/build/$ENV" -name firmware.elf 2>/dev/null | head -1; }

PASS=0; FAIL=0

# write_config <extra-cpp-lines-or-empty>
write_config() {
    # CRITICAL: remove config.h first so we never write through a symlink.
    rm -f "$CONFIG_H"
    {
        echo '#pragma once'
        echo "#include \"$BASE_CONFIG\""
        if [ -n "$1" ]; then printf '%s\n' "$1"; fi
    } > "$CONFIG_H"
}

run_case() {  # <label> <extra-cpp-lines-or-empty>
    label="$1"; extra="$2"
    echo ""
    echo "=== Case: $label ==="
    write_config "$extra"
    rm -f "$PROJ/.pio/build/$ENV/firmware.elf"
    # Capture the build status explicitly -- a `| tail` pipeline would mask
    # pio's exit code and report success on a failed build.
    build_log="$(mktemp)"
    if "$PIO" run -e "$ENV" -d "$PROJ" > "$build_log" 2>&1; then brc=0; else brc=$?; fi
    tail -4 "$build_log"; rm -f "$build_log"
    if [ "$brc" != 0 ]; then
        echo "FAIL: build failed for case '$label'"
        FAIL=$((FAIL + 1)); return
    fi
    ELF="$(find_elf)"
    if [ -z "$ELF" ]; then
        echo "FAIL: ELF not found after build for case '$label'"
        FAIL=$((FAIL + 1)); return
    fi
    echo "PASS: build succeeded for case '$label'"
    PASS=$((PASS + 1))
    # Check the OBJECT file, not the ELF: wifi_signal_eap_creds_rotated is a
    # public setter called only by cert_renewer (Mode C). In Mode B+ it is
    # unreferenced and --gc-sections strips it from the final ELF even though
    # it compiled. The .o reliably proves it was compiled (i.e. the W2 symbol
    # is at unconditional file scope, not behind the NTP_ENABLE guard).
    WIFI_O="$PROJ/.pio/build/$ENV/main/wifi.c.o"
    if [ -n "$NM" ] && [ -f "$WIFI_O" ]; then
        if "$NM" "$WIFI_O" 2>/dev/null | grep -q "wifi_signal_eap_creds_rotated$"; then
            echo "PASS: wifi_signal_eap_creds_rotated defined in wifi.c.o (W2 at file scope)"
            PASS=$((PASS + 1))
        else
            echo "FAIL: wifi_signal_eap_creds_rotated not in wifi.c.o (W2 symbol guarded out)"
            FAIL=$((FAIL + 1))
        fi
    fi
}

run_case "config.big.h, NTP on (baseline)" ""
run_case "config.big.h, NTP off (W2 guard)" "#undef NTP_ENABLE
#undef NTP_BEFORE_EAPTLS"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = "0" ]
