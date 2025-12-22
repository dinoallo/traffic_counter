FROM rust:1.98
ARG RUST_VERSION=1.98
ARG ORAS_VERSION=1.0.0

LABEL rust_version=$RUST_VERSION oras_version=$ORAS_VERSION

RUN rustup target add wasm32-wasi wasm32-wasip1

RUN arch="$(dpkg --print-architecture)"; arch="${arch##*-}"; \
    rust_version=${RUST_VERSION:-1.82}; \
    oras_version=${ORAS_VERSION:-1.0.0}; \
    echo "arch:           '$arch'"; \
    echo "rust rust_version:  '$rust_version'"; \
    echo "oras_version: '$oras_version'"; \
    case "$arch" in \
    'amd64') \
    oras_url="https://github.com/oras-project/oras/releases/download/v$oras_version/oras_${oras_version}_linux_amd64.tar.gz"; \
    ;; \
    'arm64') \
    oras_url="https://github.com/oras-project/oras/releases/download/v$oras_version/oras_${oras_version}_linux_arm64.tar.gz"; \
    ;; \
    *) echo >&2 "error: unsupported architecture '$arch' "; exit 1 ;; \
    esac; \
    echo "oras_url: '$oras_url'"; \
    wget -O oras.tgz "$oras_url" --progress=dot:giga; \
    tar -C /usr/local/bin -xzf oras.tgz && rm -rf oras.tgz; \
    echo "done";

ENV PATH=$PATH:/usr/local/bin
