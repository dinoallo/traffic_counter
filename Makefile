# Makefile - build helpers for traffic_counter

SHELL := /usr/bin/env bash

.PHONY: all build build-debug build-release fmt clippy test clean check-deps

all: build

build: build-debug

build-debug: check-deps
	cargo build

build-release: check-deps
	cargo build --release

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all-features --quiet

check-deps:
	@echo "Checking for eBPF toolchain"
	$(SHELL) scripts/check-deps.sh

clean:
	cargo clean
