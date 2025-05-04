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
	@brew install cmake ninja binaryen
else ifeq ($(shell uname),Linux)
	@sudo apt-get install -y cmake ninja-build binaryen
endif
	@cargo install wasm-pack
	@cargo install wasm-bindgen-cli
	@curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash
	@bash -c 'export NVM_DIR="$$HOME/.nvm"; . "$$NVM_DIR/nvm.sh"; nvm install 22.14.0; nvm use 22.14.0'

build: .pre-build
	@cargo make build

test: .pre-build
	@cargo make test

bench: .pre-build
	@cargo make bench

clean:
	@cargo clean
