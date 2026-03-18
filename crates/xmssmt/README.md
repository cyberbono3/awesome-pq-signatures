# XMSS^MT

Multi-tree hash-based signature scheme (RFC 8391), using the [RustCrypto `xmss`](https://crates.io/crates/xmss) pure Rust implementation.

## Backend

- Library backend: [`xmss`](https://crates.io/crates/xmss) (pure Rust, RustCrypto)
- Rust wrapper: `src/lib.rs`
- Current supported parameter sets:
  - `XMSSMT-SHA2_20/2_256`
  - `XMSSMT-SHA2_20/4_256`
  - `XMSSMT-SHA2_40/2_256`

Notes:
- XMSS^MT is stateful; each signature updates the secret key state.
- No C dependencies or OpenSSL required — pure Rust implementation.

## Project layout

- `src/lib.rs`: safe Rust wrapper (`XmssmtScheme`, keypair/sign/verify, sizes, parameter parsing)
- `src/main.rs`: executable benchmark summary for keygen/sign/verify
- `src/bin/xmssmt_bench.rs`: bench command used by `bench/run.sh`
- `benches/xmssmt_divan.rs`: `divan` benchmark suite

## Run

```bash
cargo run --release --bin xmssmt
```

Environment overrides:

- `XMSSMT_PARAM_SET` (default `XMSSMT-SHA2_20/2_256`)
- `XMSSMT_MESSAGE_SIZE` (default `1024`)
- `XMSSMT_ITERATIONS` (default `100`)
