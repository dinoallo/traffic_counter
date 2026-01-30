FROM rust:1.91-slim AS builder
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    git \
    make \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-wasip1

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo,from=rust:1.91-slim,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build --target wasm32-wasip1 -p higress-provider --release \
    && cp /workspace/target/wasm32-wasip1/release/*.wasm /main.wasm

FROM scratch AS output
COPY --from=builder /main.wasm plugin.wasm
