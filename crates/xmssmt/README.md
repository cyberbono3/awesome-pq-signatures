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

Latest run result (captured on 2026-03-18 10:25:36 UTC):

```text
=== XMSSMT-SHA2_20/2_256 (RustCrypto xmss (pure Rust)) Benchmark ===

--- Key Generation ---
Time to generate keys: 1.695662541s
Time to generate keys (ns): 1695662541

--- Signing ---
Time to sign: 3.332160416s
Time to sign (ns): 3332160416

--- Verification ---
Time to verify: 1.871667ms
Time to verify (ns): 1871667
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 68 bytes
Secret key size: 135 bytes
Signature size: 4963 bytes
```

Run the Divan benchmarks with:

```bash
cargo bench -p xmssmt-bench --bench xmssmt_divan
```

Median result (captured on 2026-03-18 10:27:16 UTC, bounded run with `--sample-count 10 --max-time 1`):

```text
Divan timing summary (median):
  keygen: 1.655 s
  sign(32): 4.762 s
  sign(1024): 4.858 s
  verify(32): 1.795 ms
  verify(1024): 1.803 ms
```

Environment overrides:

- `XMSSMT_PARAM_SET` (default `XMSSMT-SHA2_20/2_256`)
- `XMSSMT_MESSAGE_SIZE` (default `1024`)
- `XMSSMT_ITERATIONS` (default `100`)
