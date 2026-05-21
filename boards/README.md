# boards/ -- Project-local PlatformIO Board Manifests

```
boards/
  esp32-s3-devkitc-1-n16r8.json    ESP32-S3-DevKitC-1 with 16 MB flash + 8 MB OPI PSRAM
  esp32-s3-zero.json               Waveshare ESP32-S3-Zero with 4 MB flash + 2 MB QSPI PSRAM
```

PlatformIO resolves `board = <name>` by looking in this folder first, then
falling back to the platform's built-in manifests under
`~/.platformio/platforms/espressif32/boards/`. Any JSON dropped here overrides
the stock manifest of the same name, so this folder is the right place to fix
incorrect upstream metadata or to declare hardware variants that PlatformIO
does not ship.

## Why we need a custom manifest

PlatformIO's stock `esp32-s3-devkitc-1` manifest describes the **N8** variant:
8 MB flash, no PSRAM. The hardware we actually target is the **N16R8** variant
(16 MB QIO flash, 8 MB OPI PSRAM). Using the stock manifest works in practice
because most of the relevant settings are forced via `sdkconfig.defaults` and
`partitions.csv`, but PlatformIO's build banner and `pio device` output report
the wrong flash size and miss the PSRAM entirely, which is misleading during
debugging and CI log review. `esp32-s3-devkitc-1-n16r8.json` declares the
correct values up front so the banner stops lying.

## What each manifest declares

### esp32-s3-devkitc-1-n16r8.json

| Field                          | Value (n16r8)            | Why                                                |
|--------------------------------|--------------------------|----------------------------------------------------|
| `build.mcu`                    | `esp32s3`                | Target SoC                                         |
| `build.memory_type`            | `qio_opi`                | QIO flash + OPI PSRAM bus modes                    |
| `build.flash_mode`             | `qio`                    | Quad I/O flash                                     |
| `build.psram_type`             | `opi`                    | Octal SPI PSRAM (8 MB part on N16R8)               |
| `build.partitions`             | `default_16MB.csv`       | Matches the 16 MB flash size (overridden in `platformio.ini`) |
| `upload.flash_size`            | `16MB`                   | Banner + esptool argument                          |
| `upload.maximum_size`          | `16777216`               | Hard ceiling for app+OTA partitions                |
| `upload.maximum_ram_size`      | `327680`                 | 320 KB internal SRAM (PSRAM is separate)           |
| `frameworks`                   | `arduino`, `espidf`      | Both build frameworks supported                    |

`platformio.ini` references the manifest by name on both the `esp32s3` and
`wokwi` environments (`board = esp32-s3-devkitc-1-n16r8`).

### esp32-s3-zero.json

| Field                          | Value (zero)             | Why                                                |
|--------------------------------|--------------------------|----------------------------------------------------|
| `build.mcu`                    | `esp32s3`                | Target SoC (ESP32-S3FH4R2)                         |
| `build.memory_type`            | `qio_qspi`               | QIO flash + QSPI PSRAM bus modes                   |
| `build.flash_mode`             | `qio`                    | Quad I/O flash                                     |
| `build.flash_size`             | `4MB`                    | 4 MB embedded flash on FH4R2                       |
| `build.psram_type`             | `qspi`                   | Quad SPI PSRAM (2 MB embedded on FH4R2)            |
| `build.partitions`             | `default_4MB.csv`        | Matches the 4 MB flash size (overridden in `platformio.ini`) |
| `upload.flash_size`            | `4MB`                    | Banner + esptool argument                          |
| `upload.maximum_size`          | `2031616`                | Size of `ota_0` in `partitions_zero.csv` (0x1F0000) |
| `upload.maximum_ram_size`      | `327680`                 | 320 KB internal SRAM (PSRAM is separate)           |
| `frameworks`                   | `arduino`, `espidf`      | Both build frameworks supported                    |

`platformio.ini` references the manifest in the `esp32s3_zero` environment
(`board = esp32-s3-zero`).

## Adding a new board variant

1. Drop a `<name>.json` file in this folder, modeled on the existing manifest.
   The easiest starting point is to copy PlatformIO's stock manifest from
   `~/.platformio/platforms/espressif32/boards/<closest-match>.json` and edit
   the flash/PSRAM/partition fields.
2. Reference it from `platformio.ini` with `board = <name>` (no `.json`
   suffix, no path).
3. If the new variant has a different flash size, update or add a matching
   `partitions.csv` and point `board_build.partitions` at it.
4. Run `pio run -e <env>` and confirm the build banner reports the expected
   flash size and PSRAM configuration.
