# FOCAL hackathon - FRDM-MCXN947 firmware driver
#
# Targets:
#   make          build, flash, then open the UART monitor
#   make build    only compile
#   make flash    compile and load firmware onto the board
#   make monitor  open the UART console (115200 8N1)
#   make reset    soft-reset the board over CMSIS-DAP
#   make clean    delete the build tree
#   make setup    one-shot environment bootstrap (toolchain + Python + SDK)
#   make graft    recreate the symlinks that splice app/ into the SDK tree

ROOT          := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
# Which application folder to graft into the SDK:
#   app        - baseline (TLS 1.2, ECDHE-RSA)
#   app_tls13  - step 2: TLS 1.3 enabled
# e.g.  make build APP_NAME=app_tls13
APP_NAME      ?= app
APP_DIR       := $(ROOT)/$(APP_NAME)
SDK_DIR       := $(ROOT)/sdk/mcuxsdk
VENV          := $(ROOT)/.venv
TOOLCHAIN     := $(ROOT)/toolchain/arm-gnu-toolchain
BUILD_DIR     := $(SDK_DIR)/build

BOARD         := frdmmcxn947
CORE_ID       := cm33_core0
PROJECT_NAME  := focal_handshake_challenge
APP_SRC       := $(SDK_DIR)/examples/focal_challenge/freertos

PYOCD_TARGET  := mcxn947vdf
SERIAL_PORT   := /dev/ttyACM0
BAUD          := 115200

PYTHON        := $(VENV)/bin/python
WEST          := $(VENV)/bin/west
PYOCD         := $(VENV)/bin/pyocd

ELF           := $(BUILD_DIR)/$(PROJECT_NAME)_$(CORE_ID).elf
BIN           := $(BUILD_DIR)/$(PROJECT_NAME)_$(CORE_ID).bin

export ARMGCC_DIR := $(TOOLCHAIN)
export PATH       := $(VENV)/bin:$(TOOLCHAIN)/bin:$(PATH)

.DEFAULT_GOAL := all

.PHONY: all build flash monitor reset clean setup graft help

help:
	@sed -n 's/^#\s\?//;1,/^$$/p' $(firstword $(MAKEFILE_LIST))

all: flash monitor

build: graft
	@# mcuxsdk's cmake config duplicates sources on reconfigure, so `-p always`
	@# forces a pristine build every time. This adds ~15s but is reliable.
	@cd $(SDK_DIR) && $(WEST) build -p always -b $(BOARD) $(APP_SRC) -d $(BUILD_DIR) -- -Dcore_id=$(CORE_ID)
	@echo
	@echo "Built: $(ELF)"

flash: build
	@$(PYOCD) flash --target $(PYOCD_TARGET) --erase=sector $(ELF)

monitor:
	@echo "Opening $(SERIAL_PORT) @ $(BAUD) 8N1. Ctrl-A then k to quit (screen) or Ctrl-]/5 (minicom)."
	@if command -v picocom >/dev/null 2>&1; then \
		picocom -b $(BAUD) $(SERIAL_PORT); \
	elif command -v screen  >/dev/null 2>&1; then \
		screen $(SERIAL_PORT) $(BAUD); \
	elif command -v minicom >/dev/null 2>&1; then \
		minicom -D $(SERIAL_PORT) -b $(BAUD); \
	else \
		$(PYTHON) -m serial.tools.miniterm --raw $(SERIAL_PORT) $(BAUD); \
	fi

reset:
	@$(PYOCD) reset --target $(PYOCD_TARGET)

clean:
	@rm -rf $(BUILD_DIR)

graft:
	@echo "Grafting $(APP_NAME)/ into the SDK tree"
	@ln -sfn ../../../$(APP_NAME) $(SDK_DIR)/examples/focal_challenge
	@ln -sfn ../../../../../$(APP_NAME)/board_port $(SDK_DIR)/examples/_boards/$(BOARD)/focal_challenge
	@ln -sfn ../../../third_party $(SDK_DIR)/examples/focal_third_party

# The SDK's mbedTLS has no ML-KEM; patches/ carries our X25519MLKEM768 addition.
# `make patch-sdk` applies it (idempotent), `make unpatch-sdk` reverts it.
MBEDTLS_DIR   := $(SDK_DIR)/middleware/mbedtls3x
SDK_PATCH     := $(ROOT)/patches/mbedtls3x-x25519mlkem768.patch

.PHONY: patch-sdk unpatch-sdk patch-export

patch-sdk:
	@cd $(MBEDTLS_DIR) && \
	if git apply --check --reverse $(SDK_PATCH) >/dev/null 2>&1; then \
		echo "mbedtls3x: patch already applied"; \
	else \
		git apply $(SDK_PATCH) && echo "mbedtls3x: patch applied"; \
	fi

unpatch-sdk:
	@cd $(MBEDTLS_DIR) && git apply --reverse $(SDK_PATCH) && echo "mbedtls3x: patch reverted"

# Regenerate patches/ from the current (edited) SDK mbedTLS tree.
patch-export:
	@mkdir -p $(ROOT)/patches
	@cd $(MBEDTLS_DIR) && git diff > $(SDK_PATCH) && echo "Wrote $(SDK_PATCH)" && git diff --stat

setup: $(VENV) $(TOOLCHAIN) sdk graft
	@echo "Setup complete."

$(VENV):
	@python3 -m venv $(VENV)
	@$(VENV)/bin/pip install --upgrade pip
	@$(VENV)/bin/pip install west pyocd pyserial pyyaml jsonschema pykwalify

$(TOOLCHAIN):
	@mkdir -p $(ROOT)/toolchain
	@cd $(ROOT)/toolchain && \
		wget -q https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-x86_64-arm-none-eabi.tar.xz -O toolchain.tar.xz && \
		tar -xf toolchain.tar.xz && \
		mv arm-gnu-toolchain-14.2.rel1-x86_64-arm-none-eabi arm-gnu-toolchain && \
		rm toolchain.tar.xz

sdk:
	@mkdir -p $(ROOT)/sdk
	@cd $(ROOT)/sdk && [ -d .west ] || $(WEST) init -m https://github.com/nxp-mcuxpresso/mcuxsdk-manifests --mr main .
	@cd $(ROOT)/sdk && $(WEST) update --narrow \
		core CMSIS mcu-sdk-examples mcu-sdk-components mcuxsdk-tool-data \
		mcux-devices-mcx lwip mbedtls3x \
		freertos-kernel freertos-kernel-upstream \
		corehttp corehttp-upstream corejson corejson-upstream backoffalgorithm \
		aws_iot_llhttp els_pkc psa_crypto_driver tf-psa-crypto
