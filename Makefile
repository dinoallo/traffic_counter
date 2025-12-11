# Makefile - build helpers for traffic_counter

SHELL := /usr/bin/env bash

EBPF_DIR ?= ebpf
EBPF_OUT ?= target/bpf

.PHONY: all build build-ebpf build-user fmt clippy test clean deps check-ebpf

all: build-ebpf build

build: build-user

build-user:
	cargo build --release

build-ebpf:
	@echo "Building eBPF objects from $(EBPF_DIR) -> $(EBPF_OUT)"
	mkdir -p $(EBPF_OUT)
	$(SHELL) scripts/build-ebpf.sh "$(EBPF_DIR)" "$(EBPF_OUT)"

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
	rm -rf $(EBPF_OUT)
