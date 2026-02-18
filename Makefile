.PHONY: format build test dilithium-bench-example sphincs-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace