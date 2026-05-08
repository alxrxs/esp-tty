#!/usr/bin/env bash
# test/scripts/test_gen_ota_key.sh — Tests for scripts/gen_ota_key.sh
#
# Tests:
#   1. Fresh run generates all 3 files
#   2. Second run refuses (all files present)
#   3. Partial state (missing aes.key) → refuses
#   4. Partial state (missing sign.key.pem) → refuses
#   5. Delete all → run again succeeds
#   6. File size and content sanity checks
#
# Exit: 0 = PASS, 1 = FAIL

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

KEYTEST_DIR="/tmp/esp-tty-keytest-$$"
export OTA_KEYS_DIR="$KEYTEST_DIR"

fail() {
    echo "[gen_ota_key_test] FAIL — $1"
    rm -rf "$KEYTEST_DIR"
    exit 1
}

pass_step() {
    echo "[gen_ota_key_test] PASS — $1"
}

echo "[gen_ota_key_test] ── Using temp dir: $KEYTEST_DIR"
rm -rf "$KEYTEST_DIR"

# ── Step 1: Fresh run — must succeed and create all 3 files ──────────────
echo "[gen_ota_key_test] ── Step 1: Fresh run ──────────────────────────────"
if ! "$PROJECT_DIR/scripts/gen_ota_key.sh"; then
    fail "gen_ota_key.sh returned non-zero on fresh run"
fi

for f in sign.key.pem sign.pub.pem aes.key; do
    if [[ ! -f "$KEYTEST_DIR/$f" ]]; then
        fail "Expected file missing after fresh run: $KEYTEST_DIR/$f"
    fi
done
pass_step "Fresh run created all 3 files"

# ── Step 2: Second run — must refuse (all files present) ─────────────────
echo "[gen_ota_key_test] ── Step 2: Re-run (all files present, must refuse) ─"
if "$PROJECT_DIR/scripts/gen_ota_key.sh" 2>/dev/null; then
    fail "gen_ota_key.sh returned 0 when all keys already exist (expected refusal)"
fi
pass_step "Re-run correctly refused when all files present"

# ── Step 3: Partial state — missing aes.key only ─────────────────────────
echo "[gen_ota_key_test] ── Step 3: Partial state (missing aes.key) ─────────"
rm -f "$KEYTEST_DIR/aes.key"
if "$PROJECT_DIR/scripts/gen_ota_key.sh" 2>/dev/null; then
    fail "gen_ota_key.sh returned 0 with partial state (sign.*.pem present, aes.key missing)"
fi
pass_step "Correctly refused with partial state (missing aes.key)"

# ── Step 4: Partial state — missing sign.key.pem only ────────────────────
echo "[gen_ota_key_test] ── Step 4: Partial state (missing sign.key.pem) ────"
# Restore aes.key, remove sign.key.pem
openssl rand 32 > "$KEYTEST_DIR/aes.key"
rm -f "$KEYTEST_DIR/sign.key.pem"
if "$PROJECT_DIR/scripts/gen_ota_key.sh" 2>/dev/null; then
    fail "gen_ota_key.sh returned 0 with partial state (sign.key.pem missing)"
fi
pass_step "Correctly refused with partial state (missing sign.key.pem)"

# ── Step 5: Delete all — must succeed again ───────────────────────────────
echo "[gen_ota_key_test] ── Step 5: Delete all, re-run (must succeed) ───────"
rm -rf "$KEYTEST_DIR"
mkdir -p "$KEYTEST_DIR"
if ! "$PROJECT_DIR/scripts/gen_ota_key.sh"; then
    fail "gen_ota_key.sh returned non-zero on second fresh run"
fi
for f in sign.key.pem sign.pub.pem aes.key; do
    if [[ ! -f "$KEYTEST_DIR/$f" ]]; then
        fail "Expected file missing after second fresh run: $KEYTEST_DIR/$f"
    fi
done
pass_step "Second fresh run succeeded"

# ── Step 6: File content sanity checks ───────────────────────────────────
echo "[gen_ota_key_test] ── Step 6: File content checks ─────────────────────"

# aes.key must be exactly 32 bytes
AES_SIZE=$(wc -c < "$KEYTEST_DIR/aes.key")
if [[ "$AES_SIZE" -ne 32 ]]; then
    fail "aes.key is $AES_SIZE bytes, expected exactly 32"
fi
pass_step "aes.key is exactly 32 bytes"

# sign.pub.pem must start with the PEM header
PUB_HEADER=$(head -1 "$KEYTEST_DIR/sign.pub.pem")
if [[ "$PUB_HEADER" != "-----BEGIN PUBLIC KEY-----" ]]; then
    fail "sign.pub.pem does not start with '-----BEGIN PUBLIC KEY-----' (got: '$PUB_HEADER')"
fi
pass_step "sign.pub.pem starts with correct PEM header"

# sign.pub.pem must be a valid P-256 public key
PUB_CURVE=$(openssl ec -pubin -in "$KEYTEST_DIR/sign.pub.pem" -text -noout 2>&1 | grep -c "prime256v1" || true)
if [[ "$PUB_CURVE" -eq 0 ]]; then
    fail "sign.pub.pem is not a P-256 (prime256v1) public key"
fi
pass_step "sign.pub.pem is a valid P-256 public key"

# ── Cleanup ───────────────────────────────────────────────────────────────
rm -rf "$KEYTEST_DIR"

echo ""
echo "[gen_ota_key_test] ══ PASS ══"
exit 0
