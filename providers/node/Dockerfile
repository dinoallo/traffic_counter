# syntax=docker/dockerfile:1.6

FROM rust:1.91-slim AS builder
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    git \
    make \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY . .
# Perform building with caching of cargo registry and target directory
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:1.91-slim,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build -p node-provider --release && \
    cp /workspace/target/release/node-provider /node-provider

FROM gcr.io/distroless/cc-debian13:debug AS runtime

COPY --from=builder /node-provider /usr/local/bin/node-provider

ENTRYPOINT ["/usr/local/bin/node-provider"]
CMD ["--help"]
