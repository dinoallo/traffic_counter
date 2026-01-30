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

COPY . .
# Perform building with caching of cargo registry and target directory
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:1.91-slim,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo install --locked bpf-linker && \
    cargo build -p traffic-counter --release && \
    cp /workspace/target/release/traffic-counter /traffic-counter

FROM gcr.io/distroless/cc-debian13:debug AS runtime

COPY --from=builder /traffic-counter /usr/local/bin/traffic-counter

ENTRYPOINT ["/usr/local/bin/traffic-counter"]
CMD ["--help"]
