FROM ubuntu:26.04
# Set to 2 to force Docker to bypass the cache
ARG CACHEBUST=1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    curl \
    git \
    build-essential \
    sudo \
    jq \
    && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

ENV HOME=/home/ubuntu
USER ubuntu

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# WORKAROUND: Appease JetBrains Settings Sync
# The IDE expects the host's snap path. We symlink the container's binaries
# to /snap/bin so RustRover finds them automatically.
USER root
RUN mkdir -p /snap/bin \
    && ln -s $HOME/.cargo/bin/cargo /snap/bin/cargo \
    && ln -s $HOME/.cargo/bin/rustc /snap/bin/rustc \
    && ln -s $HOME/.cargo/bin/rustfmt /snap/bin/rustfmt \
    && ln -s $HOME/.cargo/bin/rustup /snap/bin/rustup
USER ubuntu

# Add Cargo to the PATH so the IDE and terminal can find it
ENV PATH="$HOME/.cargo/bin:$PATH"

# Add wasm32 target (rln-wasm compilation)
RUN rustup target add wasm32-unknown-unknown
# Add nightly toolchain: rustfmt (nightly-only group_imports) and rust-src (parallel wasm build)
RUN rustup toolchain install nightly \
    --component rustfmt --component rust-src \
    --target wasm32-unknown-unknown

# Add cargo-make (for Makefile)
RUN cargo install --locked cargo-make --version=0.37.24
# Add wasm-pack (rln-wasm compilation)
RUN cargo install --locked wasm-pack --version=0.15.0

# Set the default working directory
WORKDIR /workspace