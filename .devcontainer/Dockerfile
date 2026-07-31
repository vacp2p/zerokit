FROM ubuntu:26.04

# Silence apt prompts during the build only. As an ARG (not ENV) it applies to
# every build RUN but does not leak into the running container's interactive apt.
ARG DEBIAN_FRONTEND=noninteractive

# Base packages, incl. the system build deps (cmake, ninja) the crates need.
# No sudo: we build as root, and no-new-privileges (devcontainer.json) would
# block setuid sudo at runtime anyway.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    cmake \
    ninja-build \
    jq \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Bring in the Makefile so the container reuses the same pinned versions and
# install steps as the host and CI.
WORKDIR /workspace
COPY Makefile ./Makefile

# Node.js: same major version as the Makefile's NODE_VERSION pin.
RUN NODE_MAJOR="$(make -s print-NODE_MAJOR)" \
    && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

ENV HOME=/home/ubuntu
USER ubuntu

# Install Rust (stable) via rustup. The minimal profile skips the bundled
# rust-docs (thousands of files that bloat the image); clippy and rust-src are
# added explicitly to match CI clippy and give rust-analyzer std sources.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal -c clippy -c rust-src

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

# Toolchains via the Makefile (cmake/ninja and node already installed via apt
# above, so the apt step is skipped and NO_NVM=1 keeps nvm out of the image).
RUN make installdeps \
    && make NO_NVM=1 installdeps-wasm installdeps-wasm-parallel
