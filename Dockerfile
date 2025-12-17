# syntax=docker/dockerfile:1.6

FROM rust:1.78-slim AS builder
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    make \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal --component rust-src
RUN cargo install --locked bpf-linker

COPY Cargo.toml Cargo.lock ./
COPY traffic-counter/Cargo.toml traffic-counter/
COPY traffic-counter-common/Cargo.toml traffic-counter-common/
COPY traffic-counter-ebpf/Cargo.toml traffic-counter-ebpf/

# Cache dependencies before copying the full workspace
RUN mkdir -p traffic-counter/src traffic-counter-common/src traffic-counter-ebpf/src \
    && touch traffic-counter/src/lib.rs \
    && touch traffic-counter-common/src/lib.rs \
    && touch traffic-counter-ebpf/src/lib.rs \
    && cargo fetch --locked

COPY . .
RUN make build-release

FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app

COPY --from=builder /workspace/target/release/traffic-counter /usr/local/bin/traffic-counter

ENTRYPOINT ["traffic-counter"]
CMD ["--help"]
