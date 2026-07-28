.PHONY: all installdeps installdeps-system installdeps-tools installdeps-cross \
        installdeps-node installdeps-wasm installdeps-wasm-parallel \
        build test bench clean

# Pinned tool and runtime versions.
CARGO_MAKE_VERSION ?= 0.37.24
WASM_PACK_VERSION  ?= 0.15.0
CROSS_VERSION      ?= 0.2.5
NODE_VERSION       ?= 26.5.0
# Major version, for NodeSource's setup_<major>.x URL.
NODE_MAJOR         ?= $(firstword $(subst ., ,$(NODE_VERSION)))
NVM_VERSION        ?= 0.40.6

all: installdeps build

# Everything a native build needs; adds cross under CI.
INSTALLDEPS_DEPS := installdeps-system installdeps-tools installdeps-node
ifdef CI
INSTALLDEPS_DEPS += installdeps-cross
endif
installdeps: $(INSTALLDEPS_DEPS)

# cmake + ninja.
installdeps-system:
ifeq ($(shell uname),Darwin)
	@brew install cmake ninja
else ifeq ($(shell uname),Linux)
	@if [ -f /etc/os-release ] && grep -q "ID=nixos" /etc/os-release; then \
		echo "Detected NixOS, skipping apt installation."; \
	else \
		sudo apt-get update; \
		sudo apt-get install -y cmake ninja-build; \
	fi
endif

# cargo-make + wasm-pack, as prebuilt binaries via cargo-binstall.
installdeps-tools:
	@command -v cargo-binstall > /dev/null || \
		curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
	@cargo binstall --no-confirm cargo-make@$(CARGO_MAKE_VERSION) wasm-pack@$(WASM_PACK_VERSION)

# cross, for the release cross-compile matrix.
installdeps-cross:
	@cargo install cross --version $(CROSS_VERSION)

# Node via nvm (the devcontainer installs it via apt instead).
installdeps-node:
	@test -s "$$HOME/.nvm/nvm.sh" || curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v$(NVM_VERSION)/install.sh | bash
	@bash -c '. "$$HOME/.nvm/nvm.sh"; [ "$$(node -v 2>/dev/null)" = "v$(NODE_VERSION)" ] || nvm install $(NODE_VERSION); nvm use $(NODE_VERSION); nvm alias default $(NODE_VERSION)'

# wasm32 target, for the default and utils rln-wasm builds.
installdeps-wasm:
	@rustup target add wasm32-unknown-unknown

# Nightly + rust-src for the parallel wasm build, rustfmt for `cargo make fmt`.
installdeps-wasm-parallel:
	@rustup toolchain install nightly --profile minimal \
		--component rustfmt \
		--component rust-src \
		--target wasm32-unknown-unknown

# Print a variable, e.g. `make -s print-NODE_MAJOR`.
print-%:
	@echo '$($*)'

build:
	@cargo make build

test: build
	@cargo make test

bench: build
	@cargo make bench

clean:
	@cargo clean
