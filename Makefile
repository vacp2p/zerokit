.PHONY: all installdeps build test clean

all: .pre-build build

.pre-build:
ifeq (, $(shell which cargo-make))
	@cargo install --force cargo-make
endif

installdeps: .pre-build

build: .pre-build
	@cargo make build

test: .pre-build
	@cargo make test

clean:
	@cargo clean
