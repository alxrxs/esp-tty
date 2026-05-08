# main/ — Application Source

This directory is the ESP-IDF application component. PlatformIO treats it as the
`src_dir` (see `platformio.ini`). All files here link against wolfSSH, TinyUSB,
and ESP-IDF and cannot be compiled natively; unit-testable logic has been
extracted to `lib/`.

```
main/
  main.c              Entry point (app_main)
  ssh_server.c/h      wolfSSH listener, auth dispatch, session management
  ota_session.c/h     OTA SSH channel handler
  host_key.c/h        Ed25519 NVS key store
  wifi.c/h            Wi-Fi STA (WPA2/WPA3-Personal + optional EAP-TLS)
  usb_cdc.c/h         TinyUSB CDC ACM driver + FreeRTOS task
  config.h            Compile-time credentials (gitignored)
  config.h.example    Template to copy
  wolfssh_options.h   wolfSSH compile-time feature flags
  certs/              EAP-TLS client cert + CA cert (see certs/README.md)
  ota_keys/           OTA public key + AES key embedded into firmware
  CMakeLists.txt      ESP-IDF component registration
  idf_component.yml   IDF component manager manifest
```

## Boot sequence

```
app_main()
  1. NVS flash init (AES-XTS-256 encrypted)
       nvs_flash_read_security_cfg  →  nvs_flash_generate_keys on first boot
       nvs_flash_secure_init_partition("nvs", ...)
  2. Ring buffer allocation (16 KB each, PSRAM)
       ring_create(16*1024) x2  →  usb_to_ssh, ssh_to_usb
  3. USB CDC ACM init + task spawn
       usb_cdc_init(...)  →  usb_tx_task (FreeRTOS task)
       [skipped when BRIDGE_LOOPBACK is defined]
  4. Wi-Fi STA start
       wifi_init_sta()
  5. SSH server start
       ssh_server_start(usb_to_ssh, ssh_to_usb)
         → host_key_load_or_generate()
         → ssh_server_task (FreeRTOS task, listens TCP/2222)
  6. Rollback self-test timer
       xTimerCreate (one-shot, 30 s)
       → rollback_timer_cb calls rollback_decide() + esp_ota_mark_app_valid_cancel_rollback()
```

## main.c

`app_main` is the single entry point. It owns the lifetimes of the ring buffers
and the rollback timer. It does not run its own loop; all blocking work happens
in FreeRTOS tasks spawned by the subsystems it initialises.

The rollback timer fires 30 seconds after boot. If the SSH server is still
running (no crash, no WDT), the timer callback marks the running OTA image valid
and cancels any pending bootloader rollback. If the timer cannot be created
(memory exhaustion), `mark_app_valid_cancel_rollback` is called immediately as a
fail-safe.

## ssh_server.c

Implements the wolfSSH TCP server listening on `SSH_PORT` (default 2222).

The `ssh_server_task` FreeRTOS task calls `accept()` in a loop. When a new
connection arrives while an existing session is active, the old session is torn
down (single-session takeover).

Session teardown sequence:
1. Set `s_pump_stop = true` to signal both pump tasks.
2. Close the old file descriptor to unblock any blocked `read/write` in wolfSSH.
3. Wait on `s_pump_done_sem` twice (one give per pump task) before calling
   `wolfSSH_free`. This counting semaphore eliminates the use-after-free race
   that existed before commit `d2edfbe`.

Auth dispatch: the wolfSSH `userAuthCb` calls `pubkey_classify_user` to route
the username to the correct stored key hash (default user vs. OTA user), then
calls `pubkey_auth_check` for a constant-time hash comparison. On successful
auth of username "ota", `ota_session_run` is called instead of the bridge pump.

Cipher hardening: `wolfssh_options.h` disables AES-CBC, AES-192, SHA-1 MACs,
and DH key exchange at compile time.

## ota_session.c

Handles an OTA SSH channel: reads the binary stream from the SSH client,
feeds it to `ota_verify_feed` chunk by chunk, and calls `ota_verify_end`
after the full image is received. On success, calls `esp_restart()`. On failure,
sends an error string over the SSH channel and closes the session.

The session reads the total image length from the first `ota_verify_feed` call
(the SSH channel does not pre-announce the stream length, so the first chunk
provides the `total_image_len` based on the length field in the OTA header).

## host_key.c

Generates or loads the Ed25519 host key from encrypted NVS on every boot. If no
key is found (`ESP_ERR_NVS_NOT_FOUND`), it calls wolfCrypt to generate a new
key, stores the raw bytes in NVS, and logs the SHA-256 fingerprint to UART.

The fingerprint format is colon-separated lowercase hex
(e.g., `8b:2e:eb:84:...`) and is printed at every boot so operators can verify
the host key without a known-hosts file on first connection.

Note: the key generation path needs wolfCrypt RNG and NVS flash; it is not
covered by native unit tests. Only `format_fingerprint` (a pure formatting
helper extracted to `lib/pubkey_auth/`) is tested natively.

## wifi.c

Initialises the ESP-IDF Wi-Fi stack in STA mode. Supports two configurations
selected at compile time in `config.h`:

- WPA2/WPA3-Personal: uses `WIFI_SSID` and `WIFI_PASS`. Default.
- WPA2/WPA3-Enterprise EAP-TLS: enabled by `#define WIFI_USE_ENTERPRISE`.
  Uses `EAP_IDENTITY` and the certs in `main/certs/`. The three cert files
  (ca.pem, client.crt, client.key) are embedded into the firmware binary via
  ESP-IDF `EMBED_TXTFILES`.

The Wi-Fi event handler retries on disconnect. This path has not been tested
under real disconnect conditions; see `test/README.md` for known gaps.

## usb_cdc.c

Registers a TinyUSB CDC ACM device on the native USB port of the ESP32-S3.

Two data paths:
- TX (SSH to USB): `usb_tx_task` drains the `ssh_to_usb` ring via `ring_recv`
  and calls `tud_cdc_write`.
- RX (USB to SSH): the TinyUSB `tud_cdc_rx_cb` callback calls `ring_try_send`
  (non-blocking) to push received bytes into `usb_to_ssh`. Bytes that do not
  fit are dropped when the ring is full.

When `BRIDGE_LOOPBACK` is defined (wokwi/QEMU builds), `usb_cdc.c` is not
compiled and the two rings are wired directly together by the bridge pump
to allow loopback testing without USB hardware.
