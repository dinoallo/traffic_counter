PLUGIN_NAME ?= traffic-counter
BUILDER_REGISTRY ?= ghcr.io/dinoallo/traffic-counter/plugins/higress/
REGISTRY ?= ghcr.io/dinoallo/traffic-counter/plugins/higress/
RUST_VERSION ?= 1.98
ORAS_VERSION ?= 1.0.0
BUILDER ?= ${BUILDER_REGISTRY}wasm-rust-builder:rust${RUST_VERSION}-oras${ORAS_VERSION}
BUILD_TIME := $(shell date "+%Y%m%d-%H%M%S")
COMMIT_ID := $(shell git rev-parse --short HEAD 2>/dev/null)
IMAGE_TAG = $(if $(strip $(PLUGIN_VERSION)),${PLUGIN_VERSION},${BUILD_TIME}-${COMMIT_ID})
IMG ?= ${REGISTRY}${PLUGIN_NAME}:${IMAGE_TAG}

.DEFAULT:
build:
	DOCKER_BUILDKIT=1 docker build \
		--build-arg PLUGIN_NAME=${PLUGIN_NAME} \
		-t ${IMG} \
	    --output extensions/${PLUGIN_NAME} \
	    .
	@echo ""
	@echo "output wasm file: extensions/${PLUGIN_NAME}/plugin.wasm"

build-image:
	DOCKER_BUILDKIT=1 docker build \
	    --build-arg PLUGIN_NAME=${PLUGIN_NAME} \
	    --build-arg BUILDER=${BUILDER}  \
	    -t ${IMG} \
	    .
	@echo ""
	@echo "image:            ${IMG}"

lint-base:
	cargo fmt --all --check
	cargo clippy --workspace --all-features --all-targets
	cargo clean

test-base:
	cargo test --lib
	cargo clean

builder:
	DOCKER_BUILDKIT=1 docker build \
			--build-arg RUST_VERSION=$(RUST_VERSION) \
			--build-arg ORAS_VERSION=$(ORAS_VERSION) \
			-f Dockerfile.builder \
			-t ${BUILDER} \
			.
	@echo ""
	@echo "image: ${BUILDER}"
