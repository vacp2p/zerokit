.PHONY: all installdeps build test bench clean

all: installdeps build

.fetch-submodules:
	@git submodule update --init --recursive

.pre-build: .fetch-submodules
	@cargo install cargo-make
ifdef CI
	@cargo install cross --version 0.2.5
endif

installdeps: .pre-build
ifeq ($(shell uname),Darwin)
	@brew install ninja
else ifeq ($(shell uname),Linux)
	@if [ -f /etc/os-release ] && grep -q "ID=nixos" /etc/os-release; then \
		echo "Detected NixOS, skipping apt installation."; \
	else \
		sudo apt update; \
		sudo apt install -y cmake ninja-build; \
	fi
endif
	@which wasm-pack > /dev/null && wasm-pack --version | grep -q "0.15.0" || cargo install wasm-pack --version=0.15.0
	@test -s "$$HOME/.nvm/nvm.sh" || curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.6/install.sh | bash
	@bash -c '. "$$HOME/.nvm/nvm.sh"; [ "$$(node -v 2>/dev/null)" = "v26.5.0" ] || nvm install 26.5.0; nvm use 26.5.0; nvm alias default 26.5.0'

build:
	@cargo make build

test: build
	@cargo make test

bench: build
	@cargo make bench

clean:
	@cargo clean
