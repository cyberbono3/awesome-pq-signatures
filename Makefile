.PHONY: format build test dilithium-bench-example xmss-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace