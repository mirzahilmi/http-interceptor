FROM debian:trixie-slim AS build
WORKDIR /artifact

RUN \
  apt-get update && \
  apt-get install -y rustup build-essential && \
  rm -rf /var/lib/apt/lists/*

RUN \
  rustup install stable && \
  rustup toolchain install nightly --component rust-src && \
  rustup default stable

RUN cargo install bpf-linker

RUN \
  mkdir -p program/src program-ebpf/src program-common/src && \
  echo 'fn main() {}' > program/src/main.rs && \
  echo '#![no_std]\n#![no_main]' > program-ebpf/src/main.rs && \
  echo '#![no_std]' > program-common/src/lib.rs

COPY ./Cargo.toml ./Cargo.lock .
COPY ./program/Cargo.toml  ./program/
COPY ./program-common/Cargo.toml ./program-common/
COPY ./program-ebpf/Cargo.toml ./program-ebpf/

# see https://docs.docker.com/build/cache/optimize/#use-cache-mounts
RUN \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo build --release

COPY . .
RUN \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  set -e && \
  touch /artifact/program/src/main.rs && \
  RUST_BACKTRACE=1 cargo build --release

FROM debian:bookworm-slim
# see:
# https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#pushing-container-images
# https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#labelling-container-images
LABEL org.opencontainers.image.source="https://github.com/mirzahilmi/http_rater"
LABEL org.opencontainers.image.description="🐝 HTTP packet rate counter w/ eBPF"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

COPY --from=build /artifact/target/release/program /program
CMD ["/program"]
