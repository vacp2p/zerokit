.PHONY: all installdeps build test clean

all: .pre-build build

.fetch-submodules:
	@git submodule update --init --recursive

.pre-build: .fetch-submodules
	@cargo install cargo-make
ifdef CI
	@cargo install cross --git https://github.com/cross-rs/cross --branch main
endif

installdeps: .pre-build
ifeq ($(shell uname),Darwin)
	@brew update
	@brew install cmake ninja
else ifeq ($(shell uname),Linux)
	@sudo apt-get update
	@sudo apt-get install -y cmake ninja-build
endif
	@git clone --recursive https://github.com/WebAssembly/wabt.git
	@cd wabt && mkdir build && cd build && cmake .. -GNinja && ninja && sudo ninja install

build: .pre-build
	@cargo make build

test: .pre-build
	@cargo make test

clean:
	@cargo clean
