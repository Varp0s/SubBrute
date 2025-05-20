FROM rust:1.76-slim-bookworm AS builder

WORKDIR /app
COPY . .

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/sub_brute /app/sub_brute
COPY test-list.txt /app/test-list.txt
COPY wordlists/ /app/wordlists/

RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/app/sub_brute"]
CMD ["--help"]
