#!/usr/bin/env bash
# scripts/gen_ota_key.sh — Generate OTA signing keys for esp-tty
#
# Generates:
#   ota_keys/sign.key.pem   — ECDSA-P256 private key  (gitignored)
#   ota_keys/sign.pub.pem   — ECDSA-P256 public key   (gitignored, embedded in firmware)
#   ota_keys/aes.key        — 32 raw bytes AES-256 key (gitignored, embedded in firmware)
#
# Idempotent: refuses to overwrite existing key files.
# Requires: openssl (any modern version)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="$(dirname "$SCRIPT_DIR")/ota_keys"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { printf "${GREEN}[gen_ota_key]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[gen_ota_key]${NC} %s\n" "$*"; }
error() { printf "${RED}[gen_ota_key] ERROR:${NC} %s\n" "$*" >&2; }

# ── Prerequisite check ────────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
    error "openssl not found — please install openssl"
    exit 1
fi

# ── Guard: refuse to overwrite existing keys ──────────────────────────────────
if [[ -f "$KEY_DIR/sign.key.pem" || -f "$KEY_DIR/sign.pub.pem" || -f "$KEY_DIR/aes.key" ]]; then
    error "Key files already exist in $KEY_DIR"
    error "Delete them explicitly before regenerating (doing so invalidates any signed firmware):"
    error "  rm $KEY_DIR/sign.key.pem $KEY_DIR/sign.pub.pem $KEY_DIR/aes.key"
    exit 1
fi

mkdir -p "$KEY_DIR"

# ── ECDSA-P256 keypair ────────────────────────────────────────────────────────
info "Generating ECDSA-P256 private key..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/sign.key.pem"
chmod 600 "$KEY_DIR/sign.key.pem"

info "Extracting public key..."
openssl ec -in "$KEY_DIR/sign.key.pem" -pubout -out "$KEY_DIR/sign.pub.pem"
chmod 644 "$KEY_DIR/sign.pub.pem"

# ── AES-256 key (32 raw bytes) ────────────────────────────────────────────────
info "Generating 32-byte AES-256 key..."
openssl rand 32 > "$KEY_DIR/aes.key"
chmod 600 "$KEY_DIR/aes.key"

# ── Sanity checks ─────────────────────────────────────────────────────────────
key_size=$(wc -c < "$KEY_DIR/aes.key")
if [[ "$key_size" -ne 32 ]]; then
    error "AES key is $key_size bytes, expected 32"
    exit 1
fi

pub_check=$(openssl ec -pubin -in "$KEY_DIR/sign.pub.pem" -text -noout 2>&1 | grep -c "prime256v1" || true)
if [[ "$pub_check" -eq 0 ]]; then
    error "Public key validation failed — not a P-256 key?"
    exit 1
fi

info "Keys generated successfully:"
info "  $KEY_DIR/sign.key.pem  (ECDSA-P256 private, keep secret)"
info "  $KEY_DIR/sign.pub.pem  (ECDSA-P256 public, embedded in firmware)"
info "  $KEY_DIR/aes.key       (AES-256 raw 32B, embedded in firmware)"
warn ""
warn "IMPORTANT: Back up sign.key.pem and aes.key in a secure location."
warn "If lost, you cannot sign new firmware for devices running current firmware."
warn "These files are gitignored and will NOT be committed."
