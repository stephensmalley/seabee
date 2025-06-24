MKDOCS ?= poetry run mkdocs
PYTHON ?= poetry run python

DEMO = docs/assets/asciinema/seabee-demo.cast
DEMO_SRC = tools/seabee-autocast-demo.yaml

BUILD_PATH = ../public
BUILD_CMD = CI=true $(MKDOCS) build -d $(BUILD_PATH)

RUST_SRC = ../target/doc
RUST_TGT = docs/assets/rust

help:
	$(MKDOCS) --help

build: $(DEMO) rust-docs
	doxygen
	$(BUILD_CMD)

# Doxygen and asciinema are not supported under this rule
serve-dev:
	$(MKDOCS) serve

serve-build: $(DEMO) rust-docs
	SITE_URL="http://localhost:8080/" $(BUILD_CMD)
	$(PYTHON) -m http.server -d $(BUILD_PATH) 8080

rust-docs:
	if [ -z $$CI ]; then make -C .. docs; fi
	rm -r $(RUST_TGT) || true
	cp -r $(RUST_SRC) $(RUST_TGT)

$(DEMO): $(DEMO_SRC)
	if [ -z $$CI ]; then make -C .. release; fi
	if [ -z $$CI ]; then autocast --overwrite $(DEMO_SRC) $(DEMO); fi

.PHONY: help build serve-dev serve-build rust-docs
