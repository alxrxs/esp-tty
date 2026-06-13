# esp-tty -- convenience Makefile around PlatformIO
#
# Targets:
#   make build        [DEVNAME] [MODEL]   Compile firmware (no upload)
#   make flash        [DEVNAME] [MODEL]   Compile + flash over local USB
#   make flash-online  <DEVNAME> [MODEL]  Compile + flash via a REMOTE host's
#                                         USB cable.  The per-device config
#                                         must carry
#                                             // MAKE-FLASH-HOST: <ssh-host>
#                                         (or pass FLASH_HOST=user@host on
#                                         the command line).  For non-debug
#                                         envs this uses the USB-CDC boot-
#                                         trigger magic to enter ROM DFU
#                                         (303a:0009) and dfu-util writes +
#                                         resets -- all software-only, no
#                                         physical BOOT+EN required.  For
#                                         *_debug envs the remote host runs
#                                         esptool over USB-Serial-JTAG.
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

# flash-online destination: parsed from MAKE-FLASH-HOST in the matched config
# file, or FLASH_HOST=... on the command line wins.  This is the SSH-reachable
# machine that owns the device's USB cable (not the device's own Wi-Fi IP).
FLASH_HOST ?= $(strip $(if $(DEV_FILE),\
  $(shell sed -nE 's|^[[:space:]]*//[[:space:]]*MAKE-FLASH-HOST:[[:space:]]*([^[:space:]]+).*|\1|p' $(DEV_FILE) | head -n1),))

# Remote serial port (default /dev/ttyACM0 on the flash host).
REMOTE_PORT ?= /dev/ttyACM0

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

# flash-online: build locally, then flash via a REMOTE host's USB cable.
#
# For non-debug envs the chip is running TinyUSB-CDC (303a:xxxx) which
# blocks esptool's pyserial-based RTS reset with EPROTO; we instead use
# the boot-trigger magic on the CDC RX stream to land the chip in ROM
# USB DFU mode (303a:0009) and let dfu-util write + reset with -R.
# For *_debug envs the chip exposes the native USB-Serial-JTAG already,
# so esptool works directly on the remote host.
#
# Either way the local machine never sees the cable; everything is driven
# over SSH against the host named in `// MAKE-FLASH-HOST: <ssh-host>`
# (or FLASH_HOST=user@host on the command line).
flash-online:
	@if [ -z "$(DEV_ARG)" ] || [ -z "$(DEV_FILE)" ]; then \
	    echo "Usage: make flash-online <devname> [<model>]" >&2; \
	    echo "  devname must match main/config.<devname>.h" >&2; \
	    exit 1; \
	fi
	@if [ -z "$(FLASH_HOST)" ]; then \
	    echo "$(DEV_FILE) is missing '// MAKE-FLASH-HOST: <ssh-host>' marker." >&2; \
	    echo "(or pass FLASH_HOST=user@host on the command line)" >&2; \
	    exit 1; \
	fi
	@echo ">> selecting $(DEV_FILE)  (symlink main/config.h -> config.$(DEV_ARG).h)"
	@echo ">> flash host: $(FLASH_HOST), remote port: $(REMOTE_PORT), env: $(ENV)"
	@ln -sfn config.$(DEV_ARG).h main/config.h
	$(PIO) run -e $(ENV)
	# For non-debug envs, build a .dfu image alongside the .bin files.
	# mkdfu.py resolves JSON file paths relative to the JSON file's dir,
	# so cd into the build dir; resolve $(PYTHON) to absolute first.
	#
	# Locate mkdfu.py via PlatformIO's own packages dir (honours
	# PLATFORMIO_CORE_DIR / XDG layout / non-root installs) rather than
	# assuming /root/.platformio.
	@case "$(ENV)" in *_debug) ;; *) \
	  BUILD_DIR=".pio/build/$(ENV)"; \
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
	    cd "$$BUILD_DIR" && \
	    printf '{"flash_files":{"0x0":"bootloader.bin","0x8000":"partitions.bin","0x10000":"ota_data_initial.bin","0x20000":"firmware.bin"}}' > _dfu.json && \
	    "$$PY_ABS" "$$MKDFU" write --json _dfu.json -o firmware.dfu --pid 0x0009; \
	  fi ;; esac
	# Push artifacts + helper to the remote in one tar stream, then run it.
	@set -e; \
	files="bootloader.bin partitions.bin ota_data_initial.bin firmware.bin"; \
	case "$(ENV)" in *_debug) ;; *) files="$$files firmware.dfu" ;; esac; \
	echo ">> tar+ssh artifacts to $(FLASH_HOST):/tmp/esp-tty-flash-online/"; \
	ssh "$(FLASH_HOST)" "rm -rf /tmp/esp-tty-flash-online && mkdir -p /tmp/esp-tty-flash-online"; \
	tar -C .pio/build/$(ENV) -czf - $$files | \
	    ssh "$(FLASH_HOST)" "tar -C /tmp/esp-tty-flash-online -xzf -"; \
	scp scripts/flash_online_remote.sh "$(FLASH_HOST):/tmp/esp-tty-flash-online/"; \
	ssh "$(FLASH_HOST)" \
	    "sh /tmp/esp-tty-flash-online/flash_online_remote.sh $(ENV) /tmp/esp-tty-flash-online $(REMOTE_PORT)"

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
