## Makefile for the misgi Rust project.
## Thin wrapper around cargo so common tasks have a single, memorable entry
## point (useful for CI and for contributors who don't want to remember the
## exact cargo flags).

CARGO      ?= cargo
BIN_NAME   := misgi
TARGET_DIR := target

# Arguments forwarded to `make run`, e.g.:
#   make run ARGS="target_binary -m malware_binary --export-graphs"
ARGS ?=

.PHONY: all build release run test fmt fmt-check lint check doc clean \
        install distclean help

## Default target: format check, lint, build and test.
all: fmt-check lint build test

## Build the debug binary.
build:
	$(CARGO) build

## Build the optimized release binary.
release:
	$(CARGO) build --release

## Run the debug binary, forwarding ARGS to the CLI.
## Example: make run ARGS="bin/target -m bin/malware -e -f dot"
run:
	$(CARGO) run -- $(ARGS)

## Run the full test suite (unit + integration tests under tests/).
test:
	$(CARGO) test

## Format the codebase in place.
fmt:
	$(CARGO) fmt

## Fail if the codebase is not formatted (used in CI).
fmt-check:
	$(CARGO) fmt -- --check

## Run clippy and treat warnings as errors.
lint:
	$(CARGO) clippy --all-targets -- -D warnings

## Type-check the project without producing binaries (fast feedback loop).
check:
	$(CARGO) check --all-targets

## Build the project documentation (cargo doc).
doc:
	$(CARGO) doc --no-deps

## Remove cargo's build artifacts.
clean:
	$(CARGO) clean

## Install the release binary into ~/.cargo/bin (or $CARGO_HOME/bin).
install: release
	$(CARGO) install --path .

## Remove build artifacts and any locally exported graph files.
distclean: clean
	rm -f *.dot *.json *.gml

## List the available targets with a short description.
help:
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' \
		$(MAKEFILE_LIST) 2>/dev/null || true
	@echo "Targets: all build release run test fmt fmt-check lint check doc clean install distclean"
