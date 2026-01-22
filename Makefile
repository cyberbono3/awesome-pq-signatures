.PHONY: format build test dilithium-bench dilithium-bench-example dlithium-bench-example ilithium-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

dilithium-bench:
	BENCH_CMD="$(BENCH_CMD)" crates/dilithium/bench/run.sh

dilithium-bench-example:
	OUT_DIR=crates/dilithium/bench/results-example BENCH_CMD='true' PARAM_SETS=ML-DSA-44 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/dilithium/bench/run.sh
