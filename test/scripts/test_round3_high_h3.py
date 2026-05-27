"""
test_round3_high_h3.py -- structural pytests for round-3 HIGH fixes (H3.A..H3.D)

Each test grep-asserts an invariant in the relevant source file so a
regression is caught at commit time, not at runtime on hardware.
"""

import json
import os
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def _read(rel):
    with open(os.path.join(PROJECT_ROOT, rel)) as f:
        return f.read()


# ---------------------------------------------------------------------------
# H3.A -- host_key load path treats ANY NVS read error as "regenerate", not
#         as a fatal propagation to ESP_ERROR_CHECK.
# ---------------------------------------------------------------------------

def test_h3a_host_key_non_not_found_does_not_propagate():
    src = _read("main/host_key.c")
    # The dead "else if (err != ESP_OK) return err;" pattern must be gone.
    assert "else if (err != ESP_OK) { return err; }" not in src, (
        "host_key.c must not propagate non-NOT_FOUND NVS errors verbatim -- "
        "they should fall through to regenerate-and-save."
    )
    # The new path must log the error name on regen-on-error.
    assert "regenerating host key" in src, (
        "host_key.c must log a WARN naming the NVS error when "
        "regenerating instead of propagating."
    )
    # And there must be an ephemeral fallback so a save-failure does not
    # brick the device.
    assert "host_key_generate_ephemeral" in src, (
        "host_key.c must define an ephemeral-key fallback for the case "
        "where nvs_save_key fails after regen."
    )


# ---------------------------------------------------------------------------
# H3.B -- cred_store public API serialises through a mutex.
# ---------------------------------------------------------------------------

def test_h3b_cred_store_takes_lock_in_public_api():
    src = _read("lib/cred_store/cred_store.c")
    # Wrappers must call lock_take/lock_give around every public function.
    for fn in ("cred_store_load", "cred_store_save", "cred_store_clear"):
        pat = re.compile(
            rf"^esp_err_t {fn}\b.*?lock_take\(\).*?lock_give\(\)",
            re.DOTALL | re.MULTILINE)
        assert pat.search(src), (
            f"{fn} must take and release the cred_store mutex around its "
            f"unlocked implementation."
        )
    # The unlocked variants must also exist so the public API is thin.
    assert "cred_store_load_unlocked" in src
    assert "cred_store_save_unlocked" in src
    assert "cred_store_clear_unlocked" in src


def test_h3b_cred_store_header_documents_thread_safety():
    hdr = _read("lib/cred_store/cred_store.h")
    assert "Thread safety" in hdr or "thread safety" in hdr, (
        "cred_store.h must document the new thread-safety guarantee."
    )


# ---------------------------------------------------------------------------
# H3.C -- usb_cdc_init returns the error rather than aborting via
#         ESP_ERROR_CHECK on tinyusb init failures.
# ---------------------------------------------------------------------------

def test_h3c_usb_cdc_no_esp_error_check_on_tinyusb_init():
    src = _read("main/usb_cdc.c")
    assert "ESP_ERROR_CHECK(tinyusb_driver_install" not in src, (
        "ESP_ERROR_CHECK(tinyusb_driver_install(...)) must be replaced with "
        "an explicit error-check that returns the err."
    )
    assert "ESP_ERROR_CHECK(tinyusb_cdcacm_init" not in src, (
        "ESP_ERROR_CHECK(tinyusb_cdcacm_init(...)) must be replaced with "
        "an explicit error-check that returns the err."
    )
    # Confirm the new structured error path exists.
    assert "tinyusb_driver_install failed" in src
    assert "tinyusb_cdcacm_init failed" in src
    # Confirm partial-init cleanup is wired up.
    assert "tinyusb_driver_uninstall" in src


# ---------------------------------------------------------------------------
# H3.D -- DevKit board JSON maximum_size matches the ota_0 slot from
#         partitions.csv (4 MB), not the full 16 MB flash.
# ---------------------------------------------------------------------------

def _read_ota0_size_hex():
    """Parse partitions.csv to find the ota_0 size column."""
    with open(os.path.join(PROJECT_ROOT, "partitions.csv")) as f:
        for line in f:
            if line.strip().startswith("#") or not line.strip():
                continue
            cols = [c.strip() for c in line.split(",")]
            if len(cols) >= 5 and cols[0] == "ota_0":
                return int(cols[4], 16)
    raise AssertionError("ota_0 partition not found in partitions.csv")


def test_h3d_devkit_board_maximum_size_matches_ota_slot():
    with open(os.path.join(
            PROJECT_ROOT, "boards/esp32-s3-devkitc-1-n16r8.json")) as f:
        board = json.load(f)
    ota0_size = _read_ota0_size_hex()
    assert ota0_size == 0x400000, (
        "Expected ota_0 = 4 MB; partitions.csv changed?"
    )
    assert board["upload"]["maximum_size"] == ota0_size, (
        f"DevKit board.maximum_size = {board['upload']['maximum_size']} "
        f"but ota_0 slot is {ota0_size} (0x{ota0_size:X}).  Linking a "
        f"larger binary will silently produce an artefact that does not "
        f"fit the OTA slot."
    )
