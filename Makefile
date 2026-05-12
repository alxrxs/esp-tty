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

# Port auto-detect: prefer a CH340/CH343 USB-UART bridge (VID 1a86), since
# that is the canonical flash port on most ESP32-S3 dev boards. PlatformIO's
# own auto-detect can pick the wrong device when the ESP32-S3's native USB
# CDC is also enumerated (which is exactly what this firmware exposes).
#
# Override with `make flash PORT=/dev/ttyXXX` if needed.
PORT ?= $(firstword $(wildcard /dev/serial/by-id/usb-1a86_*))
UPLOAD_FLAGS := $(if $(PORT),--upload-port $(PORT),)

.PHONY: flash build

flash: build
	$(PIO) run -e $(ENV) --target upload $(UPLOAD_FLAGS)

build:
	$(PIO) run -e $(ENV)
