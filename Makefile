# Makefile - build helpers for traffic_counter
# ------------------------
# To build the debug version:
#   make build
# To build the release version:
#   make build-release
# To run all checks (formatting, linting, tests):
#   make prebuild
SHELL := /usr/bin/env bash

.PHONY: all build build-debug build-release fmt clippy test clean check-deps

# By default build the debug version of all packages
all: build

build: build-debug

build-debug: prebuild
	cargo build

build-release: prebuild
	cargo build --release

prebuild: check-deps fmt clippy test

fmt:
	cargo fmt --workspace --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-features --quiet

# TODO: implement a more robust dependency check for each package
check-deps:
	@echo "Checking for dependencies..."
	$(SHELL) scripts/check-deps.sh

clean:
	cargo clean
