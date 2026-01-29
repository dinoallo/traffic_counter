RUST_VERSION ?= 1.91
ORAS_VERSION ?= 1.0.0
REGISTRY ?= ghcr.io/dinoallo/traffic-counter/tools
COMMIT_ID := $(shell git rev-parse --short HEAD 2>/dev/null)
IMAGE ?= ${REGISTRY}/wasm-rust-builder:${COMMIT_ID}

.PHONY: build-image
build-image:
	DOCKER_BUILDKIT=1 docker build \
            --build-arg RUST_VERSION=$(RUST_VERSION) \
            --build-arg ORAS_VERSION=$(ORAS_VERSION) \
            -f Dockerfile \
            -t ${IMAGE} \
            .
    @echo ""
    @echo "image: ${IMAGE}"
