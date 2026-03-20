.PHONY: format build test run xmssmt-bench-example

RUNS ?= 10
OUTPUT ?= benchmarks/results.csv

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

run:
	cargo run --release --bin bench_runner -- --runs $(RUNS) --output $(OUTPUT)

xmssmt-bench-example:
	OUT_DIR=crates/xmssmt/bench/results-example BENCH_CMD='true' PARAM_SETS=XMSSMT-SHA2_20/2_256 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/xmssmt/bench/run.sh
