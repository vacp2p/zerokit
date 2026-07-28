.PHONY: all installdeps installdeps-wasm installdeps-wasm-parallel \
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

# Native build deps: cmake + ninja + cargo-make; cross added under CI.
installdeps:
ifeq ($(shell uname),Darwin)
	@command -v cmake > /dev/null && command -v ninja > /dev/null || \
		brew install cmake ninja
else ifeq ($(shell uname),Linux)
	@if command -v cmake > /dev/null && command -v ninja > /dev/null; then \
		:; \
	elif [ -f /etc/os-release ] && grep -q "ID=nixos" /etc/os-release; then \
		echo "Detected NixOS, skipping apt installation."; \
	else \
		sudo apt-get update; \
		sudo apt-get install -y cmake ninja-build; \
	fi
endif
	@command -v cargo-binstall > /dev/null || \
		curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
	@cargo make --version 2>/dev/null | grep -q "$(CARGO_MAKE_VERSION)" || \
		cargo binstall --no-confirm --force cargo-make@$(CARGO_MAKE_VERSION)
ifdef CI
	@cargo install cross --version $(CROSS_VERSION)
endif

# Everything the default rln-wasm build needs: wasm32 target, wasm-pack, node
# via nvm. NO_NVM=1 skips the node step (the devcontainer uses apt node instead).
installdeps-wasm:
	@rustup target add wasm32-unknown-unknown
	@command -v cargo-binstall > /dev/null || \
		curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
	@wasm-pack --version 2>/dev/null | grep -q "$(WASM_PACK_VERSION)" || \
		cargo binstall --no-confirm --force wasm-pack@$(WASM_PACK_VERSION)
ifndef NO_NVM
	@test -s "$$HOME/.nvm/nvm.sh" || curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v$(NVM_VERSION)/install.sh | bash
	@bash -c '. "$$HOME/.nvm/nvm.sh"; [ "$$(node -v 2>/dev/null)" = "v$(NODE_VERSION)" ] || nvm install $(NODE_VERSION); nvm use $(NODE_VERSION); nvm alias default $(NODE_VERSION)'
endif

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
