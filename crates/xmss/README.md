# XMSS

Hash-based Merkle signature scheme (RFC 8391), using the [RustCrypto `xmss`](https://crates.io/crates/xmss) pure Rust implementation.

## Backend

- Library backend: [`xmss`](https://crates.io/crates/xmss) (pure Rust, RustCrypto)
- Rust wrapper: `src/lib.rs`
- Current supported parameter sets:
  - `XMSS-SHA2_10_256`
  - `XMSS-SHA2_16_256`
  - `XMSS-SHA2_20_256`

Notes:
- XMSS is stateful; each signature updates the secret key state.
- No C dependencies or OpenSSL required — pure Rust implementation.

## Project layout

- `src/lib.rs`: safe Rust wrapper (`XmssScheme`, keypair/sign/verify, sizes, parameter parsing)
- `src/main.rs`: executable benchmark summary for keygen/sign/verify
- `src/bin/xmss_bench.rs`: bench command used by `bench/run.sh`
- `benches/xmss_divan.rs`: `divan` benchmark suite

## Run

```bash
cargo run --release --bin xmss
```

Environment overrides:

- `XMSS_PARAM_SET` (default `XMSS-SHA2_10_256`)
- `XMSS_MESSAGE_SIZE` (default `1024`)
- `XMSS_ITERATIONS` (default `100`)
