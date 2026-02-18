.PHONY: format build test lamport-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

lamport-bench-example:
	OPERATION=keygen MSG_SIZE=32 ITERATIONS=1000 DETERMINISTIC_RNG=1 cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots_bench
	OPERATION=sign MSG_SIZE=32 ITERATIONS=1000 DETERMINISTIC_RNG=1 cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots_bench
	OPERATION=verify MSG_SIZE=32 ITERATIONS=1000 DETERMINISTIC_RNG=1 cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots_bench
