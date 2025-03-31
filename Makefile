.PHONY: all installdeps build test clean

all: .pre-build build

.fetch-submodules:
	@git submodule update --init --recursive

.pre-build: .fetch-submodules
	@cargo install cargo-make
ifdef CI
	@cargo install cross --git https://github.com/cross-rs/cross.git --rev 1511a28
endif

installdeps: .pre-build
ifeq ($(shell uname),Darwin)
# commented due to https://github.com/orgs/Homebrew/discussions/4612
# @brew update
	@brew install cmake ninja wabt
else ifeq ($(shell uname),Linux)
	@sudo apt-get update
	@sudo apt-get install -y cmake ninja-build wabt
endif
	# nvm already checks if it's installed, and no-ops if it is
	@curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash || true
	@. "$$HOME/.nvm/nvm.sh" && nvm install 23.10.0 && nvm use 23.10.0 || true
	# Install wasm-pack
	@curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh || true

build: .pre-build
	@cargo make build

test: .pre-build
	@cargo make test

clean:
	@cargo clean