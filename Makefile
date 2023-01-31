.PHONY: all test clean lint

all: .pre-build
	@cargo make build

.pre-build:
ifndef $(cargo make --help)
	@cargo install --force cargo-make
endif

test: .pre-build
	@cargo make test

clean:
	@cargo clean

lint:
	cargo fmt --all --check
	cargo clippy -- -D warnings
