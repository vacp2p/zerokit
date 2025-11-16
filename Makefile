.PHONY: all installdeps build test bench clean

all: installdeps build

.fetch-submodules:
	@git submodule update --init --recursive

.pre-build: .fetch-submodules
	@cargo install cargo-make
ifdef CI
	@cargo install cross --git https://github.com/cross-rs/cross.git --rev 1511a28
endif

installdeps: .pre-build
ifeq ($(shell uname),Darwin)
	@brew install ninja
else ifeq ($(shell uname),Linux)
	@if [ -f /etc/os-release ] && grep -q "ID=nixos" /etc/os-release; then \
		echo "Detected NixOS, skipping apt-get installation."; \
	else \
		sudo apt-get install -y cmake ninja-build; \
	fi
endif
	@which wasm-pack > /dev/null && wasm-pack --version | grep -q "0.13.1" || cargo install wasm-pack --version=0.13.1
	@test -s "$$HOME/.nvm/nvm.sh" || curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash
	@bash -c '. "$$HOME/.nvm/nvm.sh"; [ "$$(node -v 2>/dev/null)" = "v22.14.0" ] || nvm install 22.14.0; nvm use 22.14.0; nvm alias default 22.14.0'

build: installdeps
	@cargo make build

test: build
	@cargo make test

bench: build
	@cargo make bench

clean:
	@cargo clean
