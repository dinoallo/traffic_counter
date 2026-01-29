PROVIDER_NAME ?= higress-l4
BUILDER_REGISTRY ?= ghcr.io/dinoallo/traffic-counter/tools
REGISTRY ?= ghcr.io/dinoallo/traffic-counter/providers/higress/
RUST_VERSION ?= 1.91
ORAS_VERSION ?= 1.0.0
#TODO: we are not using BUILDER currently?
BUILDER ?= ${BUILDER_REGISTRY}/wasm-rust-builder:v0.0.0-alpha
BUILD_TIME := $(shell date "+%Y%m%d-%H%M%S")
COMMIT_ID := $(shell git rev-parse --short HEAD 2>/dev/null)
IMAGE_TAG = $(if $(strip $(PLUGIN_VERSION)),${PLUGIN_VERSION},${BUILD_TIME}-${COMMIT_ID})
IMAGE ?= ${REGISTRY}/${PROVIDER_NAME}:${IMAGE_TAG}

.DEFAULT:
build:
	DOCKER_BUILDKIT=1 docker build \
		--build-arg PROVIDER_NAME=${PROVIDER_NAME} \
		-t ${IMAGE} \
	    --output extensions/${PROVIDER_NAME} \
	    .
	@echo ""
	@echo "output wasm file: extensions/${PROVIDER_NAME}/plugin.wasm"

build-image:
	DOCKER_BUILDKIT=1 docker build \
	    --build-arg PROVIDER_NAME=${PROVIDER_NAME} \
	    --build-arg BUILDER=${BUILDER}  \
	    -t ${IMAGE} \
	    .
	@echo ""
	@echo "image:            ${IMAGE}"

lint-base:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo clean

test-base:
	cargo test --lib
	cargo clean
