# esp-tty -- convenience Makefile around PlatformIO
#
# Targets:
#   make build                Compile firmware (no upload)
#   make flash [DEVNAME]      Compile + flash over USB
#   make ota   <DEVNAME|HOST> Compile + sign + encrypt + upload over Wi-Fi (SSH)
#
# Per-device configs (multi-ESP32 setups):
#   Keep one main/config.h.<DEVNAME> per device. Each one starts with the
#   marker line
#       // MAKE-OTA-IP: <ip-or-hostname>
#   so the Makefile knows where to ship its OTA build.
#
#   `make ota alpha` finds main/config.h.alpha, reads MAKE-OTA-IP from it,
#   copies it to main/config.h, builds, and uploads to that IP/host.
#   `make flash alpha` does the same minus the OTA -- MAKE-OTA-IP is ignored.
#
#   `make ota 192.168.1.42` (any string that doesn't name a config.h.<name>
#   file) is treated as a raw IP/hostname: the currently materialized
#   main/config.h is built and uploaded as-is, no config switch.
#
#   `make flash` and `make build` with no argument use the current
#   main/config.h unchanged. `make flash <bogus>` errors out.
#
# Other overrides:
#   make flash ENV=esp32s3 PORT=/dev/ttyACM1

ENV  ?= esp32s3

# Prefer the project-local venv if present, fall back to a system-wide `pio` on PATH.
PIO := $(shell \
  test -x .venv/bin/pio && echo .venv/bin/pio || \
  test -x venv/bin/pio  && echo venv/bin/pio  || \
  echo pio)

# Same idea for `python` -- scripts/sign_firmware.py needs the `cryptography`
# package, which requirements.txt installs into the project venv.
PYTHON := $(shell \
  test -x .venv/bin/python && echo .venv/bin/python || \
  test -x venv/bin/python  && echo venv/bin/python  || \
  echo python3)

# Auto-detect the upload port by USB Vendor ID, not by device-name pattern.
#
# Why VID-based detection: this firmware exposes the ESP32-S3's native USB
# as a CDC ACM device (the SSH<->USB bridge endpoint). On both Linux and
# macOS Big Sur+, that CDC interface enumerates with the SAME name pattern
# (/dev/ttyACM*, /dev/cu.usbmodem*) as a USB-UART bridge -- so we can't tell
# them apart by filename. The helper script asks the kernel which node
# belongs to the CH340/CH343 bridge (VID 0x1A86) and prints that.
#
# Falls back to PlatformIO's own auto-detect when the helper finds nothing.
# Override at any time with: make flash PORT=/dev/...
PORT ?= $(shell scripts/detect_upload_port.sh)
UPLOAD_FLAGS := $(if $(PORT),--upload-port $(PORT),)

FIRMWARE_BIN := .pio/build/$(ENV)/firmware.bin

# Positional argument: the first command-line goal that isn't a known target.
# May name a per-device config (main/config.h.<DEV_ARG> exists) or, for `ota`
# only, a raw IP/hostname.
DEV_ARG  := $(firstword $(filter-out ota flash build,$(MAKECMDGOALS)))
DEV_FILE := $(wildcard main/config.h.$(DEV_ARG))

# OTA destination: parsed from MAKE-OTA-IP in the matched config file, or
# DEV_ARG itself if no config file matched. Empty if no DEV_ARG was given,
# or if DEV_FILE exists but lacks the marker.
OTA_TARGET := $(strip $(if $(DEV_FILE),\
  $(shell sed -nE 's|^[[:space:]]*//[[:space:]]*MAKE-OTA-IP:[[:space:]]*([^[:space:]]+).*|\1|p' $(DEV_FILE) | head -n1),\
  $(DEV_ARG)))

.PHONY: flash build ota

build:
	$(PIO) run -e $(ENV)

flash:
	@if [ -n "$(DEV_ARG)" ] && [ -z "$(DEV_FILE)" ]; then \
	    echo "make flash $(DEV_ARG): no main/config.h.$(DEV_ARG) found." >&2; \
	    echo "Available device configs:" >&2; \
	    ls main/config.h.* 2>/dev/null | sed 's|^|  |' >&2 || echo "  (none)" >&2; \
	    exit 1; \
	fi
	@if [ -n "$(DEV_FILE)" ]; then \
	    echo ">> selecting $(DEV_FILE)"; \
	    cp $(DEV_FILE) main/config.h; \
	fi
	$(PIO) run -e $(ENV) --target upload $(UPLOAD_FLAGS)

# OTA: sign + encrypt the freshly built firmware and stream it over SSH to
# the device's `ota@` user. SSH key is resolved by the caller's ~/.ssh/config
# / agent; no -i is passed.
ota:
	@if [ -z "$(OTA_TARGET)" ]; then \
	    if [ -z "$(DEV_ARG)" ]; then \
	        echo "Usage: make ota <devname>       (uses main/config.h.<devname>)" >&2; \
	        echo "       make ota <ip-or-host>    (uses main/config.h as-is)" >&2; \
	    else \
	        echo "$(DEV_FILE) is missing a '// MAKE-OTA-IP: <ip>' marker." >&2; \
	    fi; \
	    exit 1; \
	fi
	@if [ -n "$(DEV_FILE)" ]; then \
	    echo ">> selecting $(DEV_FILE)  (OTA target: $(OTA_TARGET))"; \
	    cp $(DEV_FILE) main/config.h; \
	fi
	$(PIO) run -e $(ENV)
	$(PYTHON) scripts/sign_firmware.py $(FIRMWARE_BIN)
	ssh ota@$(OTA_TARGET) < $(FIRMWARE_BIN).ota

# Catch-all to swallow the positional argument so make doesn't try to build
# it as a target. Scoped to `ota`/`flash` invocations only -- otherwise
# `make typo` would silently succeed instead of erroring.
ifneq (,$(filter ota flash,$(MAKECMDGOALS)))
%:
	@:
endif
