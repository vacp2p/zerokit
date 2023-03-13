.PHONY: all installdeps build test clean

all: .pre-build build

.fetch-submodules:
	@git submodule update --init --recursive

.pre-build: .fetch-submodules
	@cargo install cargo-make
	@cargo install cross --git https://github.com/cross-rs/cross --branch main

installdeps: .pre-build

build: .pre-build
	@cargo make build

test: .pre-build
	@cargo make test

clean:
	@cargo clean
