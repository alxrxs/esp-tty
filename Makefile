# esp-tty -- convenience Makefile around PlatformIO
#
# Targets:
#   make build        [DEVNAME] [MODEL]   Compile firmware (no upload)
#   make flash        [DEVNAME] [MODEL]   Compile + flash over local USB
#   make flash-online  [DEVNAME] [MODEL]  Compile + flash over local USB
#                                         using the USB-CDC boot-trigger
#                                         magic + dfu-util.  Software-only:
#                                         no physical BOOT+EN press, no
#                                         pyserial-RTS reset (which fails
#                                         against the running TinyUSB CDC
#                                         with EPROTO).  Sends the magic on
#                                         the running TinyUSB endpoint to
#                                         drop the chip into ROM DFU
#                                         (303a:0009), then dfu-util writes
#                                         the image and resets.  Non-debug
#                                         envs only -- for *_debug envs the
#                                         standard `make flash` already
#                                         works (no TinyUSB in the way).
#   make ota   <DEVNAME|HOST> [MODEL]     Compile + upload over Wi-Fi
#                                         (SSH, X25519+AES-GCM)
#   make clean  [MODEL]                   Wipe .pio/build/<env>/ to force
#                                         cmake reconfigure (no MODEL = clean
#                                         every board env)
#
# Per-device configs (multi-ESP32 setups):
#   Keep one main/config.<DEVNAME>.h per device. Each one starts with the
#   marker line
#       // MAKE-OTA-IP: <ip-or-hostname>
#   so the Makefile knows where to ship its OTA build.
#
#   `make ota alpha` finds main/config.alpha.h, reads MAKE-OTA-IP from it,
#   symlinks main/config.h -> config.alpha.h, builds, and uploads to that
#   IP/host.  `make flash alpha` does the same minus the OTA.
#
#   The symlink means in-place edits to main/config.h flow through to
#   main/config.<dev>.h transparently -- no separate "save" step needed.
#   Switching devices (e.g. `make flash beta` after `make flash alpha`)
#   just repoints the symlink to config.beta.h.
#
#   `make ota 192.168.1.42` (any string that doesn't name a config.<name>.h
#   file) is treated as a raw IP/hostname: the currently materialized
#   main/config.h is built and uploaded as-is, no symlink change.
#
#   `make flash` and `make build` with no argument use the current
#   main/config.h unchanged. `make flash <bogus>` errors out.
#
# Board model positional (MODEL):
#   Pass a board model name after DEVNAME (or alone if no DEVNAME) to select
#   the PlatformIO environment.  Known models and their ENV mappings:
#     s3           (default) ESP32-S3-DevKitC-1 N16R8        -> env:esp32s3
#     s3zero                 Waveshare ESP32-S3-Zero          -> env:esp32s3_zero
#     s3debug                DevKitC-1 N16R8, debug-console   -> env:esp32s3_debug
#     s3zerodebug            ESP32-S3-Zero, debug-console     -> env:esp32s3_zero_debug
#
#   Debug-console builds omit TinyUSB and route ESP_LOG* to the USB-Serial-JTAG
#   controller (303a:1001 on USB-C).  Wi-Fi, SSH, OTA, SCEP all remain active.
#   Useful on the Zero, which has no CH340 -- you can see boot logs without an
#   external USB-UART dongle.
#
#   Examples:
#     make flash dell                   # devname=dell, model defaults to s3
#     make flash dell s3                # same as above
#     make flash dell s3zero            # devname=dell, model=s3zero
#     make flash dell s3zerodebug       # Zero board, debug-console firmware
#     make flash dell s3debug           # DevKitC-1, debug-console firmware
#     make ota   dell s3zero            # OTA build+upload, env esp32s3_zero
#     make build s3zero                 # build only, env esp32s3_zero, no devname change
#     make build s3zerodebug            # build only, debug-console env for Zero
#
#   If only one positional is given it is auto-detected: if main/config.<arg>.h
#   exists it is treated as DEVNAME; if it matches a known model name it is
#   treated as MODEL.  Explicit ENV=... always wins over the positional.
#
# Board environments (ENV=):
#   esp32s3            (default) ESP32-S3-DevKitC-1 N16R8 -- 16 MB flash, 8 MB PSRAM
#   esp32s3_zero                 Waveshare ESP32-S3-Zero  --  4 MB flash, 2 MB PSRAM
#   esp32s3_debug                DevKitC-1 N16R8, debug-console (USB-Serial-JTAG logs)
#   esp32s3_zero_debug           ESP32-S3-Zero, debug-console (USB-Serial-JTAG logs)
#
#   make build ENV=esp32s3_zero
#   make flash ENV=esp32s3_zero dell     # see Zero flashing note below
#   make ota   ENV=esp32s3_zero dell
#
# Flashing the Waveshare ESP32-S3-Zero (no CH340, no auto-reset):
#   The Zero has no USB-UART bridge and no auto-reset circuit.  To enter
#   download mode: hold the BOOT button, tap RESET, then release BOOT.
#   The ROM bootloader enumerates as VID:PID 303a:1001 (USB JTAG/serial).
#   scripts/detect_upload_port.sh detects this automatically when no CH340
#   is present.  If port detection fails, override: PORT=/dev/ttyACM1
#
# Other overrides:
#   make flash ENV=esp32s3 PORT=/dev/ttyACM1

# Prefer the project-local venv if present, fall back to a system-wide `pio` on PATH.
PIO := $(shell \
  test -x .venv/bin/pio && echo .venv/bin/pio || \
  test -x venv/bin/pio  && echo venv/bin/pio  || \
  echo pio)

# Same idea for `python` -- scripts/ota_send.py needs paramiko + cryptography,
# which requirements.txt installs into the project venv.
PYTHON := $(shell \
  test -x .venv/bin/python && echo .venv/bin/python || \
  test -x venv/bin/python  && echo venv/bin/python  || \
  echo python3)

# Positional argument parsing.
#
# Anything in MAKECMDGOALS that isn't a known target is a positional.  Up to
# two positionals are accepted, in either order: a per-device config name
# (main/config.<x>.h exists) and a board model name (in $(KNOWN_MODELS)).
KNOWN_MODELS          := s3 s3zero s3debug s3zerodebug
ENV_OF_s3             := esp32s3
ENV_OF_s3zero         := esp32s3_zero
ENV_OF_s3debug        := esp32s3_debug
ENV_OF_s3zerodebug    := esp32s3_zero_debug

POSITIONALS := $(filter-out ota flash flash-online build clean test test-py,$(MAKECMDGOALS))

# Pick the model positional (whichever positional matches KNOWN_MODELS).
MODEL_ARG := $(strip $(foreach p,$(POSITIONALS),$(if $(filter $(p),$(KNOWN_MODELS)),$(p),)))

# The non-model positional, if any, is the devname (or raw IP for `ota`).
DEV_ARG  := $(firstword $(filter-out $(KNOWN_MODELS),$(POSITIONALS)))
DEV_FILE := $(wildcard main/config.$(DEV_ARG).h)

# Resolve ENV: explicit `make ENV=...` wins; else model positional; else default.
# ENV_EXPLICIT records whether the user named a specific env -- used by `make
# clean` to decide between cleaning one env or all of them.
ENV_EXPLICIT := no
ifeq ($(origin ENV),command line)
  ENV_EXPLICIT := yes
else ifneq ($(MODEL_ARG),)
  ENV_EXPLICIT := yes
  ENV := $(ENV_OF_$(MODEL_ARG))
else
  ENV := esp32s3
endif

# Full list of board envs, used by `make clean` when no env was specified.
ALL_BOARD_ENVS := esp32s3 esp32s3_zero esp32s3_debug esp32s3_zero_debug

# Auto-detect the upload port by USB Vendor ID, not by device-name pattern.
#
# Why VID-based detection: this firmware exposes the ESP32-S3's native USB
# as a CDC ACM device (the SSH<->USB bridge endpoint). On both Linux and
# macOS Big Sur+, that CDC interface enumerates with the SAME name pattern
# (/dev/ttyACM*, /dev/cu.usbmodem*) as a USB-UART bridge -- so we can't tell
# them apart by filename. The helper script asks the kernel which node
# belongs to the CH340/CH343 bridge (VID 0x1A86) -- and on Zero-class boards
# without a CH340, falls back to the ESP32-S3 ROM bootloader (303a:1001).
#
# Override at any time with: make flash PORT=/dev/...
PORT ?= $(shell scripts/detect_upload_port.sh)
UPLOAD_FLAGS := $(if $(PORT),--upload-port $(PORT),)

FIRMWARE_BIN := .pio/build/$(ENV)/firmware.bin

# OTA destination: parsed from MAKE-OTA-IP in the matched config file, or
# DEV_ARG itself if no config file matched. Empty if no DEV_ARG was given,
# or if DEV_FILE exists but lacks the marker.
OTA_TARGET := $(strip $(if $(DEV_FILE),\
  $(shell sed -nE 's|^[[:space:]]*//[[:space:]]*MAKE-OTA-IP:[[:space:]]*([^[:space:]]+).*|\1|p' $(DEV_FILE) | head -n1),\
  $(DEV_ARG)))

# flash-online uses the running TinyUSB CDC endpoint to deliver the
# boot-trigger magic.  scripts/detect_trigger_port.sh asks the kernel for the
# actual USB VID:PID and returns the 0x303A node that is NOT the ROM
# USB-Serial-JTAG (0x1001) or ROM DFU (0x0009) -- i.e. the running app's CDC.
# (A /dev/serial/by-id/ name glob can't be used: the firmware sets custom USB
# string descriptors, so its by-id node carries no VID:PID substring to match.)
# Override at the command line with TRIG_PORT=/dev/ttyACMn.
TRIG_PORT ?= $(shell scripts/detect_trigger_port.sh)

.PHONY: flash flash-online build ota test test-py clean

# If two positionals are given but neither is a known model, the second one
# is a typo -- error rather than silently swallow it via the catch-all below.
ifeq ($(words $(POSITIONALS)),2)
  ifeq ($(MODEL_ARG),)
    $(error two positional args given but neither is a known board model: '$(POSITIONALS)'. Known models: $(KNOWN_MODELS))
  endif
endif

build:
	$(PIO) run -e $(ENV)

# Wipe .pio/build/<env>/ AND the top-level sdkconfig.<env> so the next build
# re-runs cmake configure and re-merges sdkconfig.defaults from scratch.  Use
# this when a CMake-time dependency wasn't picked up because the cache predates
# it, OR when sdkconfig.defaults was edited (ESP-IDF takes the existing merged
# sdkconfig.<env> as truth and only consults sdkconfig.defaults on first
# generation, so edits to defaults are silently ignored without this clean).
#
#   make clean              # cleans every board env
#   make clean s3zero       # cleans only esp32s3_zero
#   make clean ENV=esp32s3  # cleans only esp32s3 (explicit override)
clean:
ifeq ($(ENV_EXPLICIT),yes)
	$(PIO) run -e $(ENV) --target fullclean
	@rm -fv sdkconfig.$(ENV)
else
	@for env in $(ALL_BOARD_ENVS); do \
	    echo ">> fullclean $$env"; \
	    $(PIO) run -e $$env --target fullclean; \
	    rm -fv sdkconfig.$$env; \
	done
endif

# Pure-Python tests for scripts/: no hardware, no network, no SSH.
# Covers scripts/apply_managed_patches_cmake.py and the OTA wire protocol
# (scripts/ota_send.py via test/scripts/test_ota_send_unit.py +
# test/scripts/test_ota_protocol_e2e.py).
test-py:
	$(PYTHON) -m pytest test/scripts/test_ota_send_unit.py \
	                    test/scripts/test_ota_protocol_e2e.py \
	                    test/scripts/test_scep_protocol_e2e.py -v
	$(PYTHON) test/scripts/test_apply_patches.py

# Aggregate: native (PlatformIO Unity) + python script tests.
test: test-py
	$(PIO) test -e native

flash:
	@if [ -n "$(DEV_ARG)" ] && [ -z "$(DEV_FILE)" ]; then \
	    echo "make flash $(DEV_ARG): no main/config.$(DEV_ARG).h found." >&2; \
	    echo "Available device configs:" >&2; \
	    ls main/config.*.h 2>/dev/null | grep -vE 'config\.(h|example)\.h$$' \
	        | sed 's|^|  |' >&2 || echo "  (none)" >&2; \
	    exit 1; \
	fi
	@if [ -n "$(DEV_FILE)" ]; then \
	    echo ">> selecting $(DEV_FILE) (symlink main/config.h -> config.$(DEV_ARG).h)"; \
	    ln -sfn config.$(DEV_ARG).h main/config.h; \
	fi
	$(PIO) run -e $(ENV) --target upload $(UPLOAD_FLAGS)

# flash-online: local DFU flash, no BOOT+EN press required.
#
# The running app's TinyUSB CDC stack rejects esptool's pyserial RTS reset
# (EPROTO), so `make flash` against a running non-debug build fails.  This
# target sidesteps that: it sends the USB-CDC boot-trigger magic on the
# CDC RX stream, which the firmware's matcher converts into a clean reboot
# into ROM USB DFU (303a:0009).  dfu-util -R then writes flash + resets.
# Entirely software-driven -- no buttons, no SSH.
#
# Non-debug envs only.  For *_debug envs there is no TinyUSB CDC to
# capture the cable, so `make flash` already works -- use that.
flash-online:
	@case "$(ENV)" in *_debug) \
	    echo "flash-online is non-debug-only (env=$(ENV) has no TinyUSB CDC)." >&2; \
	    echo "Use 'make flash $(DEV_ARG) $(MODEL_ARG)' instead." >&2; \
	    exit 1 ;; esac
	@if [ -n "$(DEV_ARG)" ] && [ -z "$(DEV_FILE)" ]; then \
	    echo "make flash-online $(DEV_ARG): no main/config.$(DEV_ARG).h found." >&2; \
	    exit 1; \
	fi
	@if [ -n "$(DEV_FILE)" ]; then \
	    echo ">> selecting $(DEV_FILE)  (symlink main/config.h -> config.$(DEV_ARG).h)"; \
	    ln -sfn config.$(DEV_ARG).h main/config.h; \
	fi
	$(PIO) run -e $(ENV)
	# Build firmware.dfu alongside the .bin files (if not already current).
	# mkdfu.py resolves JSON file paths relative to the JSON file's dir,
	# so cd into the build dir; resolve $(PYTHON) to absolute first.
	# Locate mkdfu.py via PlatformIO's packages dir (honours
	# PLATFORMIO_CORE_DIR / XDG layout / non-root installs).
	# Pass -fs with the env's real flash size (mkdfu defaults to 2MB, which
	# bounds the ROM DFU flashchip geometry below the Zero's 4MB ota_0/ota_1
	# region -- writes past 0x200000 would fail/wrap).  Read it from the
	# generated sdkconfig.<env> (4MB Zero, 16MB DevKit) before the cd.
	@BUILD_DIR=".pio/build/$(ENV)"; \
	if [ -f "$$BUILD_DIR/firmware.dfu" ] && \
	   [ "$$BUILD_DIR/firmware.dfu" -nt "$$BUILD_DIR/firmware.bin" ] && \
	   [ "$$BUILD_DIR/firmware.dfu" -nt "$$BUILD_DIR/bootloader.bin" ] && \
	   [ "$$BUILD_DIR/firmware.dfu" -nt "$$BUILD_DIR/partitions.bin" ] && \
	   [ "$$BUILD_DIR/firmware.dfu" -nt "$$BUILD_DIR/ota_data_initial.bin" ]; then \
	  echo ">> firmware.dfu up to date, skipping mkdfu.py"; \
	else \
	  PIO_PKG_DIR="$$($(PYTHON) -c 'from platformio.project.config import ProjectConfig; print(ProjectConfig().get_optional_dir("packages"))' 2>/dev/null)"; \
	  test -n "$$PIO_PKG_DIR" || PIO_PKG_DIR="$$HOME/.platformio/packages"; \
	  MKDFU="$$(find "$$PIO_PKG_DIR" -maxdepth 3 -name mkdfu.py -path '*framework-espidf*' 2>/dev/null | head -1)"; \
	  test -n "$$MKDFU" || { echo "could not find mkdfu.py under $$PIO_PKG_DIR"; exit 1; }; \
	  PY_ABS="$$(realpath $(PYTHON))"; \
	  FLASH_SIZE="$$(sed -nE 's/^CONFIG_ESPTOOLPY_FLASHSIZE="([^"]+)"/\1/p' sdkconfig.$(ENV))"; \
	  test -n "$$FLASH_SIZE" || { echo "could not read CONFIG_ESPTOOLPY_FLASHSIZE from sdkconfig.$(ENV)" >&2; exit 1; }; \
	  echo ">> DFU flash geometry: $$FLASH_SIZE (from sdkconfig.$(ENV))"; \
	  cd "$$BUILD_DIR" && \
	  printf '{"flash_files":{"0x0":"bootloader.bin","0x8000":"partitions.bin","0x10000":"ota_data_initial.bin","0x20000":"firmware.bin"}}' > _dfu.json && \
	  "$$PY_ABS" "$$MKDFU" write --json _dfu.json -o firmware.dfu --pid 0x0009 -fs "$$FLASH_SIZE"; \
	fi
	# Send boot-trigger magic to the running TinyUSB CDC endpoint.
	@if [ -z "$(TRIG_PORT)" ]; then \
	    echo "could not find the TinyUSB CDC endpoint." >&2; \
	    echo "looked for a running 303a:* CDC endpoint (excluding ROM 1001/0009)" >&2; \
	    echo "override with TRIG_PORT=/dev/ttyACMn" >&2; \
	    exit 1; \
	fi
	@echo ">> sending boot-trigger magic to $(TRIG_PORT)"
	$(PYTHON) scripts/reboot_to_bootloader.py $(TRIG_PORT)
	# Wait up to 6s for the ROM DFU endpoint to enumerate, then dfu-util -R.
	@echo ">> waiting for 303a:0009 (ROM DFU)..."
	@for i in $$(seq 1 30); do \
	    if lsusb -d 303a:0009 >/dev/null 2>&1; then break; fi; \
	    sleep 0.2; \
	done
	@lsusb -d 303a:0009 >/dev/null 2>&1 || { \
	    echo "303a:0009 (ROM DFU) did not appear within 6s" >&2; exit 2; }
	# dfu-util commonly reports "can't detach" on the post-download reset
	# because by then the chip is gone -- which is the success signal we
	# wanted.  Treat "Download done." + "Resetting USB" as success.
	# LC_ALL=C pins dfu-util output to English so the grep works under
	# localised locales (e.g. de_DE: "Fertig.").
	@set +e; \
	dfu_out=$$(LC_ALL=C dfu-util -d 0x303a:0x0009 -a 0 -R \
	                   -D ".pio/build/$(ENV)/firmware.dfu" 2>&1); \
	dfu_rc=$$?; \
	echo "$$dfu_out" | tail -5; \
	if echo "$$dfu_out" | grep -q 'Download done\.' && \
	   echo "$$dfu_out" | grep -q 'Resetting USB'; then \
	    echo ">> dfu-util write+reset complete (rc=$$dfu_rc treated as OK)"; \
	    exit 0; \
	fi; \
	echo "dfu-util failed (rc=$$dfu_rc)" >&2; exit $$dfu_rc

# OTA: stream the freshly built firmware to the device's `ota@` user.
# Encryption is negotiated inside the SSH session via X25519 + AES-256-GCM
# (see main/ota_session.c and scripts/ota_send.py); no pre-shared key files
# are needed.  SSH auth uses the caller's ~/.ssh/config / agent.
ota:
	@if [ -z "$(OTA_TARGET)" ]; then \
	    if [ -z "$(DEV_ARG)" ]; then \
	        echo "Usage: make ota <devname>       (uses main/config.<devname>.h)" >&2; \
	        echo "       make ota <ip-or-host>    (uses main/config.h as-is)" >&2; \
	    else \
	        echo "$(DEV_FILE) is missing a '// MAKE-OTA-IP: <ip>' marker." >&2; \
	    fi; \
	    exit 1; \
	fi
	@if [ -n "$(DEV_FILE)" ]; then \
	    echo ">> selecting $(DEV_FILE)  (symlink main/config.h -> config.$(DEV_ARG).h, OTA target: $(OTA_TARGET))"; \
	    ln -sfn config.$(DEV_ARG).h main/config.h; \
	fi
	$(PIO) run -e $(ENV)
	$(PYTHON) scripts/ota_send.py $(OTA_TARGET) $(FIRMWARE_BIN)

# Catch-all to swallow positional arguments so make doesn't try to build
# them as targets.  Scoped to the targets that accept positionals --
# otherwise `make typo` would silently succeed instead of erroring.
ifneq (,$(filter ota flash flash-online build clean,$(MAKECMDGOALS)))
%:
	@:
endif
