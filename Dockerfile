# syntax=docker/dockerfile:1

FROM rust:1.96-trixie AS builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && cp target/release/atlas-transaction-decoder /usr/local/bin/atlas-transaction-decoder

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /usr/local/bin/atlas-transaction-decoder /usr/local/bin/atlas-transaction-decoder

ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=28884 \
    HTML_TITLE="Atlas Transaction Decoder" \
    MAX_INPUT_BYTES=2097152 \
    DEFAULT_CHAIN_ID=1337 \
    RPC_URL=""

EXPOSE 28884
ENTRYPOINT ["atlas-transaction-decoder"]
