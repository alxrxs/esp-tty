# esp-tty — Nano Console Server

SSH-over-Wi-Fi serial console bridge for ESP32-S3.

```
ssh -p 2222 console@<esp32-ip>
```

Lands directly in the Linux server's `getty` login prompt.  The ESP32 is the cable.

## Quick start

### 1. Configure credentials

```bash
cp main/config.h.example main/config.h
$EDITOR main/config.h
```

Fill in:
- `WIFI_SSID` / `WIFI_PASS` — your network
- `SSH_PORT` — default `2222`
- `AUTHORIZED_PUBKEY` — your `~/.ssh/id_ed25519.pub` content

### 2. Build and flash

```bash
pio run -e esp32s3 -t upload
```

Hold BOOT on the board, plug the **UART** USB port, then release BOOT.

### 3. Hardware bring-up checklist

1. Open UART monitor: `pio device monitor`  
   Watch for the assigned IP address and the host key SHA-256 fingerprint.

2. Move the USB-C cable to the **native USB** port on the ESP32-S3.  
   On the Linux server:
   ```bash
   dmesg | grep ttyACM
   lsusb | grep NanoConsole
   ```

3. Enable a serial getty on the Linux server:
   ```bash
   sudo systemctl enable --now serial-getty@ttyACM0.service
   ```

4. From your laptop:
   ```bash
   ssh -p 2222 console@<ip-from-uart-log>
   ```
   Verify the fingerprint matches what was printed to the UART log on first boot.

5. Smoke test:
   ```bash
   yes | head -10000
   ```
   Verify no drops or corruption.

### Reset host key

```bash
idf.py erase-flash
```

Next boot generates a fresh host key.  No eFuses are burned.

## Development

### Run native unit tests

```bash
pio test -e native
```

Runs on Linux and macOS without hardware.  Tests: ring buffer semantics, bridge pump correctness.

### Build firmware only

```bash
pio run -e esp32s3
```

## Architecture

```
ssh client ──TCP:2222──► ESP32-S3 (wolfSSH, ED25519 host key)
                            │
                            ▼
                      USB CDC (TinyUSB)
                            │ USB-C cable
                            ▼
                  Linux host /dev/ttyACM0 ──► serial-getty ──► bash
```

Three FreeRTOS tasks, two 16 KB PSRAM ring buffers:

| Task | Role |
|---|---|
| `wifi_task` (inside wifi_init_sta) | WPA2/WPA3-Personal STA, reconnect on drop |
| `ssh_server_task` | wolfSSH listener TCP/2222, single-session takeover, pubkey auth |
| `usb_tx_task` | Drains `ssh_to_usb` ring → CDC TX |
| TinyUSB internal task | CDC RX callback → `usb_to_ssh` ring |

## Security notes

- **Auth**: pubkey only (no passwords). Configured at compile time in `config.h`.
- **Host key**: ED25519, generated on first boot, stored in NVS. Fingerprint printed to UART.
- **NVS encryption**: disabled in v1 (plain NVS). See `sdkconfig.defaults` for the extension point.
- **No eFuses burned**: everything is reversible via `idf.py erase-flash`.
