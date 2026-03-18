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

Latest run result (captured on 2026-03-18 09:59:22 UTC):

```text
=== XMSS-SHA2_10_256 (RustCrypto xmss (pure Rust)) Benchmark ===

--- Key Generation ---
Time to generate keys: 1.633048625s
Time to generate keys (ns): 1633048625

--- Signing ---
Time to sign: 1.627532625s
Time to sign (ns): 1627532625

--- Verification ---
Time to verify: 888.083 us
Time to verify (ns): 888083
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 68 bytes
Secret key size: 136 bytes
Signature size: 2500 bytes
```

Run the Divan benchmarks with:

```bash
cargo bench -p xmss-bench --bench xmss_divan
```

Median result (captured on 2026-03-18 09:58:33 UTC, bounded run with `--sample-count 10 --max-time 1`):

```text
Divan timing summary (median):
  keygen: 1.645 s
  sign(32): 3.304 s
  sign(1024): 3.294 s
  verify(32): 808.1 us
  verify(1024): 853.8 us
```

Environment overrides:

- `XMSS_PARAM_SET` (default `XMSS-SHA2_10_256`)
- `XMSS_MESSAGE_SIZE` (default `1024`)
- `XMSS_ITERATIONS` (default `100`)
