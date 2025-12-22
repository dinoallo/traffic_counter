FROM rust:1.98 AS builder
WORKDIR /workspace
RUN rustup target add wasm32-wasip1
ARG PLUGIN_NAME="traffic-counter"
ARG BUILD_OPTS="--release"
ARG PREBUILD=".prebuild"
COPY . .
WORKDIR /workspace/extensions/$PLUGIN_NAME
RUN if [ -f $PREBUILD ]; then sh $PREBUILD; fi
RUN cargo build --target wasm32-wasip1 $BUILD_OPTS \
    && cp target/wasm32-wasip1/release/*.wasm /main.wasm \
    && cargo clean

FROM scratch AS output
COPY --from=builder /main.wasm plugin.wasm
