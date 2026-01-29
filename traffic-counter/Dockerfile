# syntax=docker/dockerfile:1.6

FROM rust:1.91-slim AS builder
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    git \
    make \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal --component rust-src
RUN rustup toolchain install stable --profile minimal
RUN cargo install --locked bpf-linker

# Cache dependencies before copying the full workspace
RUN mkdir -p src \
    && touch src/lib.rs \
    && cargo fetch --locked

COPY . .
RUN make build-release

FROM gcr.io/distroless/cc-debian12:debug AS runtime

COPY --from=builder /workspace/target/release/traffic-counter /usr/local/bin/traffic-counter

ENTRYPOINT ["/usr/local/bin/traffic-counter"]
CMD ["--help"]
