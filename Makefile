.PHONY: format build test dilithium-bench-example sphincs-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

dilithium-bench-example:
	OUT_DIR=crates/dilithium/bench/results-example BENCH_CMD='true' PARAM_SETS=ML-DSA-44 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/dilithium/bench/run.sh

sphincs-bench-example:
	OUT_DIR=crates/sphincs/bench/results-example BENCH_CMD='true' PARAM_SETS=SPHINCS-256f MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/sphincs/bench/run.sh
