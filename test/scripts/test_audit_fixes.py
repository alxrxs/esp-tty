#!/usr/bin/env python3
"""
test/scripts/test_audit_fixes.py
-- Regression guards for the security audit fixes B1, B2, B4, B5, B7.

These are source-level greps that lock in behavioural invariants which would
silently regress if the underlying code were rewritten.  They are intentionally
strict: a refactor that changes the spelling must update this test.

  B1 -- main.c NULL-checks the "nvs" partition lookup before deref.
  B2 -- main.c distinguishes corrupt-key-part from first-boot with ESP_LOGE.
  B4 -- ota_session.c validates plaintext_len against the actual OTA slot
        size (esp_ota_get_next_update_partition->size) BEFORE PSRAM alloc.
  B5 -- scep_enroll.c does NOT log the full CN or private-key-DER-size at
        INFO level; both are LOGD now.
  B7 -- sdkconfig.esp32s3 uses the custom OTA partition table, not
        SINGLE_APP.
"""

import os
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))


def _read(rel):
    path = os.path.join(PROJECT_DIR, rel)
    with open(path, "r") as f:
        return f.read()


# ---------------------------------------------------------------------------
# B1: nvs partition NULL guard in main.c
# ---------------------------------------------------------------------------
def test_b1_main_nvs_partition_null_guarded():
    src = _read("main/main.c")
    # The pattern: find nvs_part and check NULL before deref.
    # We search for a NULL-check on nvs_part in the erase path.
    assert re.search(
        r"esp_partition_find_first\(\s*ESP_PARTITION_TYPE_DATA,\s*"
        r"ESP_PARTITION_SUBTYPE_DATA_NVS,",
        src,
    ), "nvs partition lookup not found"
    # There must be an `if (!nvs_part)` or `nvs_part == NULL` check before
    # the dereference of nvs_part->size.
    # Easiest: assert that "if (!nvs_part)" appears in the file.
    assert "if (!nvs_part)" in src, \
        "NULL-check on nvs_part is missing (B1 regression)"


# ---------------------------------------------------------------------------
# B2: corrupt-key-part branch logs at ESP_LOGE
# ---------------------------------------------------------------------------
def test_b2_corrupt_key_part_logged_at_error():
    src = _read("main/main.c")
    # The corrupt branch must NOT share the first-boot ESP_LOGI line; it
    # must use ESP_LOGE and mention that credentials will be destroyed.
    # We look for an ESP_LOGE on the line following ESP_ERR_NVS_CORRUPT_KEY_PART.
    m = re.search(
        r"ESP_ERR_NVS_CORRUPT_KEY_PART[^}]+?ESP_LOG([EW])",
        src,
        re.DOTALL,
    )
    assert m, "no ESP_LOGE/W follows ESP_ERR_NVS_CORRUPT_KEY_PART handling"
    assert m.group(1) == "E", \
        "corrupt-key-part path must log at ESP_LOGE, not LOGW/LOGI"
    # And the NO_FREE_PAGES erase path must also LOGE about credential loss.
    assert re.search(
        r"ESP_ERR_NVS_NO_FREE_PAGES[^}]+?ESP_LOGE",
        src,
        re.DOTALL,
    ), "NO_FREE_PAGES erase path must log at ESP_LOGE"


# ---------------------------------------------------------------------------
# B4: ota_session plaintext_len bounded by actual partition size
# ---------------------------------------------------------------------------
def test_b4_ota_plaintext_len_validated_against_partition_size():
    src = _read("main/ota_session.c")
    # The partition lookup must appear BEFORE the plaintext_len check,
    # which must compare against next->size (captured as max_plaintext).
    assert "esp_ota_get_next_update_partition" in src, \
        "OTA partition lookup missing"
    # The new variable bounds the cap.
    assert "max_plaintext" in src, \
        "max_plaintext bound missing (B4 regression)"
    # The fixed 4 MiB cap should be gone (no more MAX_OTA_PLAINTEXT macro).
    assert "MAX_OTA_PLAINTEXT" not in src, \
        "stale 4MiB MAX_OTA_PLAINTEXT cap still present (B4 regression)"
    # The check must compare plaintext_len against max_plaintext.
    assert re.search(
        r"plaintext_len\s*>\s*max_plaintext", src
    ), "plaintext_len bound check against max_plaintext missing"


# ---------------------------------------------------------------------------
# B5: sensitive ESP_LOGI lines have been moved to LOGD
# ---------------------------------------------------------------------------
def test_b5_cn_not_logged_at_info():
    src = _read("main/scep_enroll.c")
    # The old line "URL=%s CN=%s" must not appear at ESP_LOGI anymore.
    bad = re.search(r'ESP_LOGI\([^;]*CN=%s', src)
    assert bad is None, \
        f"CN logged at INFO: {bad.group(0)} (B5 regression)"


def test_b5_private_key_size_not_logged_at_info():
    src = _read("main/scep_enroll.c")
    bad = re.search(r'ESP_LOGI\([^;]*Private key DER', src)
    assert bad is None, \
        f"Private key DER size logged at INFO: {bad.group(0)} (B5 regression)"


def test_b5_transaction_id_not_logged_at_info():
    src = _read("main/scep_enroll.c")
    bad = re.search(r'ESP_LOGI\([^;]*transactionID', src)
    assert bad is None, \
        f"transactionID logged at INFO: {bad.group(0)} (B5 regression)"


# ---------------------------------------------------------------------------
# B7: sdkconfig.esp32s3 uses custom OTA partition table
# ---------------------------------------------------------------------------
def test_b7_esp32s3_sdkconfig_uses_custom_partition_table():
    src = _read("sdkconfig.esp32s3")
    assert "# CONFIG_PARTITION_TABLE_SINGLE_APP is not set" in src, \
        "CONFIG_PARTITION_TABLE_SINGLE_APP=y is still set (B7 regression)"
    assert "CONFIG_PARTITION_TABLE_CUSTOM=y" in src, \
        "CONFIG_PARTITION_TABLE_CUSTOM=y missing (B7 regression)"
    assert 'CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"' in src, \
        "CONFIG_PARTITION_TABLE_FILENAME wrong (B7 regression)"


def test_b7_defaults_pin_partition_table():
    src = _read("sdkconfig.defaults")
    assert "CONFIG_PARTITION_TABLE_CUSTOM=y" in src, \
        "sdkconfig.defaults must pin CONFIG_PARTITION_TABLE_CUSTOM (B7)"


# ---------------------------------------------------------------------------
# B6: ca_chain is built from multiple bundle slots, not just ca_cert
# ---------------------------------------------------------------------------
def test_b6_ca_chain_includes_ra_certs():
    src = _read("main/scep_enroll.c")
    # The fix concatenates ca_cert_der, ra_sign_cert_der, ra_encrypt_cert_der.
    assert "ra_sign_cert_der" in src, \
        "ra_sign_cert_der must be included in ca_chain (B6 regression)"
    assert "ra_encrypt_cert_der" in src, \
        "ra_encrypt_cert_der must be included in ca_chain (B6 regression)"
    # The single-cert direct memcpy from cab.ca_cert_der should be gone.
    # Search for the OLD pattern: a single memcpy(creds.ca_chain, cab.ca_cert_der, cab.ca_cert_len)
    # without surrounding dedup logic.
    assert "chain_off" in src, \
        "chain_off accumulator missing -- ca_chain not deduped (B6 regression)"
