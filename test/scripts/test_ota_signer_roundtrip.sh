#!/usr/bin/env bash
# test/scripts/test_ota_signer_roundtrip.sh
#
# Host signer <-> on-device verifier roundtrip test.
#
# Steps:
#   1. Generate fresh OTA keys in a temp dir (not the project's ota_keys/)
#   2. Generate a 256-byte deterministic dummy firmware
#   3. Sign the firmware with scripts/sign_firmware.py
#   4. Compile roundtrip_verify.c (links lib/ota_verify and stubs) with gcc
#   5. Run roundtrip_verify against the signed image -- expect OTA_VERIFY_OK
#   6. Re-run with --tamper-byte to flip a ciphertext byte -- expect failure
#
# Exit: 0 = PASS, 1 = FAIL

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

TMPDIR="${TMPDIR:-/tmp}"
WORKDIR="$TMPDIR/esp-tty-signer-test"

PASS_REASON=""
FAIL_REASON=""

fail() {
    FAIL_REASON="$1"
    echo "[signer_roundtrip] FAIL -- $FAIL_REASON"
    exit 1
}

echo "[signer_roundtrip] -- Working dir: $WORKDIR"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/keys"

# -- Step 1: Generate OTA keys in temp dir ---------------------------------

echo "[signer_roundtrip] -- Step 1: Generate OTA keys ---------------------"

# gen_ota_key.sh generates into $PROJECT_DIR/ota_keys by default via relative path.
# We invoke openssl directly to generate keys in our temp dir.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/keys/sign.key.pem"
openssl ec -in "$WORKDIR/keys/sign.key.pem" -pubout -out "$WORKDIR/keys/sign.pub.pem" 2>/dev/null
openssl rand 32 > "$WORKDIR/keys/aes.key"

echo "[signer_roundtrip] Keys generated in $WORKDIR/keys/"

# -- Step 2: Generate deterministic 256-byte dummy firmware ---------------

echo "[signer_roundtrip] -- Step 2: Generate dummy firmware ----------------"
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)))" > "$WORKDIR/dummy.bin"
DUMMY_SIZE=$(wc -c < "$WORKDIR/dummy.bin")
echo "[signer_roundtrip] Dummy firmware: $DUMMY_SIZE bytes"

# -- Step 3: Sign the firmware --------------------------------------------

echo "[signer_roundtrip] -- Step 3: Sign firmware ------------------------"
python3 "$PROJECT_DIR/scripts/sign_firmware.py" \
    "$WORKDIR/dummy.bin" \
    --out "$WORKDIR/dummy.bin.ota" \
    --key "$WORKDIR/keys/sign.key.pem" \
    --aes "$WORKDIR/keys/aes.key"

OTA_SIZE=$(wc -c < "$WORKDIR/dummy.bin.ota")
echo "[signer_roundtrip] Signed image: $OTA_SIZE bytes"

# -- Step 4: Compile roundtrip_verify -------------------------------------

echo "[signer_roundtrip] -- Step 4: Compile roundtrip_verify ---------------"

BINARY="$WORKDIR/roundtrip_verify"

gcc -O0 -g \
    -DOTA_VERIFY_NATIVE_TEST \
    -I "$PROJECT_DIR/lib/ota_verify" \
    -I "$PROJECT_DIR/test/stubs" \
    -I "$PROJECT_DIR/test/stubs/wolfssl" \
    "$SCRIPT_DIR/roundtrip_verify.c" \
    "$PROJECT_DIR/lib/ota_verify/ota_verify.c" \
    -lcrypto \
    -o "$BINARY"

echo "[signer_roundtrip] Compiled: $BINARY"

# -- Step 5: Run roundtrip_verify -- expect success ------------------------

echo "[signer_roundtrip] -- Step 5: Verify signed image (expect OK) ---------"

if ! "$BINARY" \
        "$WORKDIR/dummy.bin.ota" \
        "$WORKDIR/keys/sign.pub.pem" \
        "$WORKDIR/keys/aes.key"; then
    fail "roundtrip_verify returned non-zero for a valid signed image"
fi

echo "[signer_roundtrip] Verification OK (pass case)"

# -- Step 6: Tamper one ciphertext byte -- expect failure ------------------

echo "[signer_roundtrip] -- Step 6: Tamper image (expect FAIL) --------------"

# The ciphertext starts at offset 44 (after the 44-byte header).
# Flip byte 50 (within ciphertext) -- this should break the ECDSA signature.
TAMPER_OFFSET=50

if "$BINARY" \
        "$WORKDIR/dummy.bin.ota" \
        "$WORKDIR/keys/sign.pub.pem" \
        "$WORKDIR/keys/aes.key" \
        --tamper-byte "$TAMPER_OFFSET" 2>&1; then
    fail "roundtrip_verify returned 0 for a tampered image (expected failure)"
fi

echo "[signer_roundtrip] Tamper-fail case: PASS (verifier correctly rejected tampered image)"

# -- Step 7: 0-byte firmware -- signer must succeed, verifier must reject ---

echo "[signer_roundtrip] -- Step 7: 0-byte firmware (expect OTA_VERIFY_ERR_EMPTY_IMAGE) -"

# Generate an empty firmware file
python3 -c "import sys; sys.stdout.buffer.write(b'')" > "$WORKDIR/empty.bin"
EMPTY_SIZE=$(wc -c < "$WORKDIR/empty.bin")
echo "[signer_roundtrip] Empty firmware: $EMPTY_SIZE bytes"

# Sign should succeed (host tool has no objection to empty input)
python3 "$PROJECT_DIR/scripts/sign_firmware.py" \
    "$WORKDIR/empty.bin" \
    --out "$WORKDIR/empty.bin.ota" \
    --key "$WORKDIR/keys/sign.key.pem" \
    --aes "$WORKDIR/keys/aes.key"
echo "[signer_roundtrip] Sign of empty firmware: OK"

# Verifier must REJECT the empty image (OTA_VERIFY_ERR_EMPTY_IMAGE = -11)
# roundtrip_verify exits 1 on any verification failure, which is what we want.
EMPTY_OTA_SIZE=$(wc -c < "$WORKDIR/empty.bin.ota")
echo "[signer_roundtrip] Signed empty image: $EMPTY_OTA_SIZE bytes"

if "$BINARY" \
        "$WORKDIR/empty.bin.ota" \
        "$WORKDIR/keys/sign.pub.pem" \
        "$WORKDIR/keys/aes.key" 2>&1; then
    fail "roundtrip_verify accepted a 0-byte firmware (expected OTA_VERIFY_ERR_EMPTY_IMAGE)"
fi
echo "[signer_roundtrip] Empty firmware correctly rejected by verifier: PASS"

# -- Step 8: 1 MB firmware roundtrip --------------------------------------

echo "[signer_roundtrip] -- Step 8: 1 MB firmware roundtrip -----------------"

python3 -c "
import sys, os
# 1 MB of pseudo-random data (deterministic)
import hashlib
data = b''
for i in range(256):
    data += hashlib.sha256(i.to_bytes(4, 'little')).digest() * 128
sys.stdout.buffer.write(data[:1024*1024])
" > "$WORKDIR/large.bin"

LARGE_SIZE=$(wc -c < "$WORKDIR/large.bin")
echo "[signer_roundtrip] Large firmware: $LARGE_SIZE bytes"

python3 "$PROJECT_DIR/scripts/sign_firmware.py" \
    "$WORKDIR/large.bin" \
    --out "$WORKDIR/large.bin.ota" \
    --key "$WORKDIR/keys/sign.key.pem" \
    --aes "$WORKDIR/keys/aes.key"

LARGE_OTA_SIZE=$(wc -c < "$WORKDIR/large.bin.ota")
echo "[signer_roundtrip] Signed large image: $LARGE_OTA_SIZE bytes"

if ! "$BINARY" \
        "$WORKDIR/large.bin.ota" \
        "$WORKDIR/keys/sign.pub.pem" \
        "$WORKDIR/keys/aes.key"; then
    fail "roundtrip_verify failed for 1 MB firmware"
fi
echo "[signer_roundtrip] 1 MB firmware verified OK: PASS"

# -- Done -----------------------------------------------------------------

echo ""
echo "[signer_roundtrip] == PASS =="
exit 0
