# Makefile - build helpers for traffic_counter

SHELL := /usr/bin/env bash

.PHONY: all build build-debug build-release fmt clippy test clean check-deps

all: build

build: build-debug

build-debug: check-deps fmt clippy test
	cargo build

build-release: check-deps fmt clippy test
	cargo build --release

fmt:
	cargo fmt --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all-features --quiet

check-deps:
	@echo "Checking for dependencies..."
	$(SHELL) scripts/check-deps.sh

clean:
	cargo clean
