.PHONY: format build test

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace
<<<<<<< HEAD

dilithium-bench-example:
	OUT_DIR=crates/dilithium/bench/results-example BENCH_CMD='true' PARAM_SETS=ML-DSA-44 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/dilithium/bench/run.sh

fors-bench-example:
	OUT_DIR=crates/fors/bench/results-example BENCH_CMD='true' PARAM_SETS=SLH-DSA-SHA2-128s MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/fors/run.sh
=======
>>>>>>> master
