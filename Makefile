# Makefile - build helpers for traffic_counter

SHELL := /usr/bin/env bash

.PHONY: all build build-debug build-release fmt clippy test clean deps check-ebpf

all: build

build: build-debug

build-debug: check-ebpf
	cargo build

build-release: check-ebpf
	cargo build --release

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

deps:
	@echo "Required: cargo, rustc, clang, bpftool"

check-ebpf:
	@echo "Checking for eBPF toolchain"
	$(SHELL) scripts/check-deps.sh

clean:
	cargo clean
