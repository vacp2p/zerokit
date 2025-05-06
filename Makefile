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
	@cargo install wasm-pack --version=0.13.1 --force
	@cargo install wasm-bindgen-cli --version=0.2.100 --force
	@curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash
	@bash -c 'export NVM_DIR="$$HOME/.nvm"; . "$$NVM_DIR/nvm.sh"; nvm install 22.14.0; nvm use 22.14.0'

build: installdeps
	@cargo make build

test: build
	@cargo make test

bench: build
	@cargo make bench

clean:
	@cargo clean
