ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
CARGO = cargo

DEBUG_SRC = target/debug
RELEASE_SRC = target/release

PROGRAM = seabee
PROGRAM_SRC_DEBUG = $(DEBUG_SRC)/$(PROGRAM)
PROGRAM_SRC_RELEASE = $(RELEASE_SRC)/$(PROGRAM)
PROGRAM_PATH = /usr/sbin/$(PROGRAM)

CLI = seabeectl
CLI_SRC_DEBUG = $(DEBUG_SRC)/$(CLI)
CLI_SRC_RELEASE = $(RELEASE_SRC)/$(CLI)
CLI_PATH = /usr/sbin/$(CLI)

SERVICE = seabee.service
SERVICE_STDOUT_SRC = install/stdout.service
SERVICE_JOURNALD_SRC = install/journald.service
SERVICE_PATH = /etc/systemd/system/$(SERVICE)

CONFIG_PATH = /etc/seabee/config.yaml

.PHONY: default_target clean all release daemon-run daemon-enable install-ci install install-release-ci install-release run run-release enable enable-release test test-ci test-release test-release-ci fmt clippy ci docs update

default_target: all

# if missing or outdated, install the daemon service into systemd
$(SERVICE_PATH): $(SERVICE_STDOUT_SRC) $(SERVICE_JOURNALD_SRC)
	@ systemctl -q is-active systemd-journald >/dev/null && \
	if [ $$? -eq 0 ]; then \
		sudo cp $(SERVICE_JOURNALD_SRC) $(SERVICE_PATH); \
	else \
		sudo cp $(SERVICE_STDOUT_SRC) $(SERVICE_PATH); \
	fi
	sudo systemctl daemon-reload

clean:
	@$(CARGO) clean
	@make -C tests/kmod_test clean
	@make -C tests/kmod_example clean

# default: compile for development
all:
	@$(CARGO) build

# compile with optimizations for release
release:
	@$(CARGO) build --release

# run the daemon with the currently installed binaries
daemon-run:
	@sudo systemctl start $(SERVICE)
	@sudo journalctl -u $(SERVICE) -f

# enable the daemon to run on reboot with the currently installed binaries
daemon-enable:
	@sudo systemctl enable $(SERVICE)

# install the debug binaries and configs
install-ci: $(SERVICE_PATH)
	sudo cp $(CLI_SRC_DEBUG) $(CLI_PATH)
	sudo cp $(PROGRAM_SRC_DEBUG) $(PROGRAM_PATH)

# compile and install the debug binaries and configs
install: all install-ci
# install the release binaries and configs
install-release-ci: $(SERVICE_PATH)
	sudo cp $(PROGRAM_SRC_RELEASE) $(PROGRAM_PATH)
	sudo cp $(CLI_SRC_RELEASE) $(CLI_PATH)
# compile and install the release binaries and configs
install-release: release install-release-ci

# run the daemon with up-to-date binaries
run: install daemon-run
run-release: install-release daemon-run

# enable the daemon to boot with up-to-date binaries
enable: install daemon-enable
enable-release: install-release daemon-enable

# compile and test debug binaries
test: install test-ci
	$(CARGO) test
# only test debug binaries (used by CI)
test-ci: install-ci
	@make -C tests test
# compile and test release binaries
test-release: install-release test-release-ci
	$(CARGO) test --release
# only test release binaries (used by CI)
test-release-ci: install-release-ci
	@make -C tests test-release

# Generates an unencrypted RSA key pair
gen-root-key-ci:
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out seabee-root-private-key.pem
	openssl pkey -in seabee-root-private-key.pem -out seabee-root-public-key.pem -pubout

# Generates an encrypted RSA key pair
gen-root-key:
	openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out seabee-root-private-key.pem
	openssl pkey -in seabee-root-private-key.pem -out seabee-root-public-key.pem -pubout

# Copies public key from 'gen-root-key' to the Seabee root key path
install-root-key:
	sudo mkdir -p /etc/seabee
	sudo cp seabee-root-public-key.pem /etc/seabee/seabee_root_key.pem

# format all Rust code
fmt:
	@$(CARGO) fmt

# lint all Rust code
clippy:
	@$(CARGO) clippy --all-targets --all-features --no-deps

ci:
	@./ci/run_megalinter.sh

docs:
	@$(CARGO) doc --no-deps

# update dependencies
update:
	@./scripts/update_dependencies.sh
