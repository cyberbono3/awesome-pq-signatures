.PHONY: format build test dilithium-bench-example hss-bench-example lms-bench-example

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

dilithium-bench-example:
	OUT_DIR=crates/dilithium/bench/results-example BENCH_CMD='true' PARAM_SETS=ML-DSA-44 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/dilithium/bench/run.sh

hss-bench-example:
	OUT_DIR=crates/hss/bench/results-example BENCH_CMD='true' PARAM_SETS=HSS_L2_LMS_SHA256_M32_H5+LMOTS_SHA256_N32_W4 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/hss/bench/run.sh

lms-bench-example:
	OUT_DIR=crates/lms/bench/results-example BENCH_CMD='true' PARAM_SETS=LMS_SHA256_M32_H5+LMOTS_SHA256_N32_W4 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/lms/bench/run.sh
