.PHONY: format build test

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace
