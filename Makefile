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
	@brew install cmake ninja wabt
else ifeq ($(shell uname),Linux)
	@sudo apt-get update
	@sudo apt-get install -y cmake ninja-build wabt
endif
	@if [ ! -d "$$HOME/.nvm" ]; then \
		curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash; \
	fi
	@bash -c 'export NVM_DIR="$$HOME/.nvm" && \
		[ -s "$$NVM_DIR/nvm.sh" ] && \. "$$NVM_DIR/nvm.sh" && \
		nvm install 22.14.0 && \
		nvm use 22.14.0'
	@curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
	@echo "\033[1;32m>>> Now run this command to activate Node.js 22.14.0 in your current terminal: \033[1;33msource $$HOME/.nvm/nvm.sh && nvm use 22.14.0\033[0m"

build: .pre-build
	@cargo make build

test: .pre-build
	@cargo make test

bench: .pre-build
	@cargo make bench

clean:
	@cargo clean