.PHONY: format build test dilithium-bench-example xmssmt-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

dilithium-bench-example:
	OUT_DIR=crates/dilithium/bench/results-example BENCH_CMD='true' PARAM_SETS=ML-DSA-44 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/dilithium/bench/run.sh

xmssmt-bench-example:
	OUT_DIR=crates/xmssmt/bench/results-example BENCH_CMD='true' PARAM_SETS=XMSSMT-SHA2_20/2_256 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/xmssmt/bench/run.sh
