# XMSS

Hash-based Merkle signature scheme (RFC 8391), implemented via Rust FFI over the XMSS C reference implementation.

## Backend

- Library backend: `xmss-reference` (vendored C sources in `vendor/xmss-reference`)
- Rust wrapper: `src/lib.rs`
- Current supported parameter sets:
  - `XMSS-SHA2_10_256`
  - `XMSS-SHA2_16_256`
  - `XMSS-SHA2_20_256`

Notes:
- XMSS is stateful; each signature updates the secret key state.
- The C reference backend requires OpenSSL `libcrypto` headers/libraries for SHA-2.

## Project layout

- `src/lib.rs`: safe Rust wrapper (`XmssScheme`, keypair/sign/verify, sizes, parameter parsing)
- `src/main.rs`: executable benchmark summary for keygen/sign/verify
- `src/bin/xmss_bench.rs`: bench command used by `bench/run.sh`
- `benches/xmss_divan.rs`: `divan` benchmark suite
- `bench/run.sh`: metadata-rich benchmark harness with JSON/CSV outputs

## Run

```bash
cargo run -p xmss --release --bin xmss
```

Environment overrides:

- `XMSS_PARAM_SET` (default `XMSS-SHA2_10_256`)
- `XMSS_MESSAGE_SIZE` (default `1024`)
- `XMSS_ITERATIONS` (default `100`)

## Divan benchmark

Quick smoke run:

```bash
cargo bench -p xmss --bench xmss_divan -- --test
```

Regular benchmark run:

```bash
cargo bench -p xmss --bench xmss_divan
```

## Structured benchmark harness

```bash
OUT_DIR=crates/xmss/bench/results-example \
BENCH_CMD='cargo run -p xmss --release --bin xmss_bench --' \
PARAM_SETS=XMSS-SHA2_10_256 \
MSG_SIZES=32 \
ITERATIONS=3 \
WARMUP_RUNS=0 \
RUNS=1 \
OPERATIONS=keygen,sign,verify \
PRINT_SUMMARY=1 \
crates/xmss/bench/run.sh
```

## Latest local results

Date: 2026-02-18

`src/main.rs` (`XMSS_PARAM_SET=XMSS-SHA2_10_256`, `XMSS_MESSAGE_SIZE=1024`, `XMSS_ITERATIONS=10`):

- `public_key_bytes: 68`
- `secret_key_bytes: 136`
- `signature_bytes: 2500`
- `keygen_avg_ns: 1123783295`
- `sign_avg_ns: 1104597258`
- `verify_avg_ns: 557675`

`bench/run.sh` sample (`MSG_SIZES=32`, `ITERATIONS=3`, `RUNS=1`):

- `keygen_avg_ns: 1098196764`
- `sign_avg_ns: 1099239070`
- `verify_avg_ns: 560708`
- Output files:
  - `bench/results-example/run-20260218T200105Z-74065.json`
  - `bench/results-example/run-20260218T200105Z-74065.csv`

`divan --test` output:

- `keygen`
- `sign` (`32`, `1024`)
- `verify` (`32`, `1024`)

## Benchmark environment (captured)

- Host: `andreis-MacBook-Pro.local`
- OS/kernel: `Darwin 25.1.0 arm64`
- Rust: `rustc 1.87.0-nightly (f4a216d28 2025-03-02)`
- CPU model: `unknown` in sandbox
- RAM: `unknown` in sandbox
