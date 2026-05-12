# esp-tty — convenience Makefile around PlatformIO
#
# Targets:
#   make build    Compile firmware (no upload)
#   make flash    Compile + flash to the device  (default)
#
# You can override the build environment and the upload port:
#   make flash ENV=esp32s3 PORT=/dev/ttyACM1

ENV  ?= esp32s3

# Prefer the project-local venv if present (created by `python -m venv .venv`),
# fall back to a system-wide `pio` on PATH.
PIO := $(shell test -x .venv/bin/pio && echo .venv/bin/pio || echo pio)

# Auto-detect the upload port by USB Vendor ID, not by device-name pattern.
#
# Why VID-based detection: this firmware exposes the ESP32-S3's native USB
# as a CDC ACM device (the SSH↔USB bridge endpoint). On both Linux and
# macOS Big Sur+, that CDC interface enumerates with the SAME name pattern
# (/dev/ttyACM*, /dev/cu.usbmodem*) as a USB-UART bridge — so we can't tell
# them apart by filename. The helper script asks the kernel which node
# belongs to the CH340/CH343 bridge (VID 0x1A86) and prints that.
#
# Falls back to PlatformIO's own auto-detect when the helper finds nothing.
# Override at any time with: make flash PORT=/dev/...
PORT ?= $(shell scripts/detect_upload_port.sh)
UPLOAD_FLAGS := $(if $(PORT),--upload-port $(PORT),)

.PHONY: flash build

flash: build
	$(PIO) run -e $(ENV) --target upload $(UPLOAD_FLAGS)

build:
	$(PIO) run -e $(ENV)
