# esp-tty Test Suite

The test suite has four tiers: native host unit tests, integration and
system scripts, on-device smoke tests, and a simulator configuration for
interactive or scripted firmware runs. Each tier has its own subdirectory
with a detailed README; this document is a concise overview and entry
point.

## Tiers at a glance

| Tier | Directory | How to run | Requires hardware? |
|---|---|---|---|
| Native unit tests | [`test/native/`](native/README.md) | `pio test -e native` | No |
| Integration scripts | [`test/scripts/`](scripts/README.md) | `pytest` / `bash` per script | No (QEMU) |
| On-device smoke | [`test/embedded/`](embedded/) | `pio test -e esp32s3` | Yes |
| Simulator config | [`test/wokwi/`](wokwi/README.md) | Wokwi extension or wokwi.com | No |

## Native unit tests

Extensive Unity-based unit suites run on the host with no ESP32-S3, no
emulator, and no network. See [`test/native/README.md`](native/README.md)
for the per-suite breakdown. Each suite is a directory under `test/native/`
following the convention `test_X/test_X.c`. Crypto suites link against
OpenSSL 3 + the host's system `libmbedtls` / `libmbedcrypto` /
`libmbedx509` via thin shim headers in [`test/stubs/`](stubs/README.md).

## Integration scripts

Mix of pytest-driven Python and shell scripts that test properties beyond
the scope of unit tests: build reproducibility, patch idempotency, OTA and
SCEP protocol round-trips, and full firmware boot under QEMU. All run on a
Linux host; none require real ESP32-S3 hardware.

| Script | What it does |
|---|---|
| `test_qemu_boot.py` | Builds the wokwi firmware, merges a 16 MB flash image with esptool, boots under `qemu-system-xtensa`, asserts SSH listen + NVS keygen log lines appear within the timeout |
| `test_qemu_nvs_persistence.py` | Runs two back-to-back QEMU boots; asserts the host-key fingerprint is identical across reboots |
| `test_clean_build.sh` | Wipes build cache, substitutes a minimal `config.h`, runs `pio run -e wokwi` and `pio test -e native`, then a second incremental build to confirm patch idempotency |
| `test_apply_patches.py` | Unit-tests `scripts/apply_managed_patches_cmake.py`: happy-path apply, idempotency, malformed-patch error, missing-patches-dir no-op |
| `test_ota_send_unit.py` | Unit tests for the OTA-over-SSH client: HKDF, AES-GCM roundtrip, key derivation, framing |
| `test_ota_protocol_e2e.py` | End-to-end OTA protocol against an in-process FakeDevice -- success, tampered, truncated, replay |
| `test_scep_protocol_e2e.py` | End-to-end SCEP enrolment against an in-process FakeNdesCA -- success, failure, pending, malformed CertRep, single/multi-cert bundle parsing |

Run the pytest tests with `venv/bin/pytest test/scripts/test_*.py`.
See [`test/scripts/README.md`](scripts/README.md) for prerequisites and
exact invocation syntax.

## On-device smoke

[`test/embedded/`](embedded/) holds firmware tests that link against the
full ESP-IDF stack and require real hardware. The single suite
`test_scep_proto_smoke` exercises the SCEP wire-protocol roundtrip
end-to-end on a real ESP32-S3. Gated on a build flag; not run as part of
normal CI.

## Simulator

[`test/wokwi/`](wokwi/README.md) holds the Wokwi simulator manifest
(`wokwi.toml`) and circuit diagram (`diagram.json`) for the `wokwi`
PlatformIO environment. That environment builds with `BRIDGE_LOOPBACK=1`,
which wires the two ring buffers back-to-back instead of connecting to a
USB host, allowing the SSH bridge loop to run in a network-only simulated
environment. The same binary produced by `pio run -e wokwi` is also used
by `test_qemu_boot.py` and `test_qemu_nvs_persistence.py`.

## Known coverage gaps

The following components have no automated test coverage. They require real
hardware or deep mocking that does not yet exist:

- **`host_key.c` -- key generation + NVS persistence**: needs wolfCrypt RNG
  and NVS flash emulation. Only `format_fingerprint()` is tested natively.
- **`wifi.c` -- event handlers and reconnect logic**: the pure decision
  function (`wifi_decide_next_step`) is fully tested in `test_wifi_state`;
  the imperative `wifi_mode_psk` / `wifi_mode_enterprise` /
  `wifi_init_smart` wrappers that drive the ESP-IDF event loop and EAP
  supplicant require hardware.
- **`usb_cdc.c` -- TinyUSB RX/TX wiring**: the drain loop is extracted to
  `lib/usb_cdc_drain/` and tested in `test_cdc_drain`; callback
  registration and the `usb_tx_task` loop require hardware.
- **`ssh_server.c` -- accept loop, session preemption, pump tasks**:
  requires wolfSSH and a live TCP connection. Helper formatters it uses are
  covered in their own native suites.
- **`ota_session.c` -- streaming verify-and-flash flow**: the wire
  protocol is covered by `test_ota_protocol_e2e` (Python FakeDevice); the
  wolfSSL X25519 / HKDF / AES-GCM integration and the `esp_ota_*` flash
  writes require hardware.
- **`scep_enroll.c` / `cert_renewer.c`**: the protocol primitives are
  covered by `test_scep_proto` and `test_scep_protocol_e2e`; the
  orchestrator code that glues them to `cred_store`, `wifi.c`, and the
  EAP supplicant requires hardware. The embedded smoke
  (`test/embedded/test_scep_proto_smoke`) exercises the on-device mbedTLS
  path against a real network.
- **E2E SSH session into QEMU**: `qemu-system-xtensa` for ESP32-S3 has no
  NIC emulation the firmware can drive; a full session test requires real
  hardware.
- **`main.c` -- NVS encryption init flow**: encrypted NVS cannot be
  inspected from the host; tested only indirectly via QEMU boot log.

## Security model note

The device uses NVS encryption (AES-XTS-256) with the key stored in the
`nvs_keys` partition -- no eFuses are burned. This is intentional: the
project leaves all eFuse bits unprogrammed so the device can be reflashed
freely during development. The trade-off is that an attacker with physical
flash access can extract the NVS key. The SSH host key, authorised public
keys, and the SCEP-enrolled client cert + private key all live in NVS; none
enable privilege escalation beyond serial console access.
