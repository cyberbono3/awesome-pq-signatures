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

## XMSS vs XMSS^MT

`XMSS^MT` is the multi-tree variant standardized alongside XMSS in RFC 8391. Both are stateful hash-based signature schemes, but they target slightly different operational tradeoffs.

- `XMSS`: single Merkle tree, simpler structure, simpler state handling, and usually the easier starting point when one tree is enough for the signing budget you need.
- `XMSS^MT`: multiple stacked trees, more structural complexity, but designed to scale to larger overall state spaces than a single XMSS tree.
- `XMSS`: good fit when you want the more direct construction and simpler implementation/operational story.
- `XMSS^MT`: better fit when you need the multi-tree construction and want to compare against the `XMSSMT-*` parameter sets supported in this workspace.

In this repository:
- XMSS crate: [`crates/xmss`](./README.md)
- XMSS^MT crate: [`crates/xmssmt`](../xmssmt/README.md)

## Project layout

- `src/lib.rs`: safe Rust wrapper (`XmssScheme`, keypair/sign/verify, sizes, parameter parsing)
- `src/main.rs`: standard workspace benchmark binary (`--format human|json --message-size N`)
- `src/bin/xmss_bench.rs`: bench command used by `bench/run.sh`
- `benches/xmss_divan.rs`: `divan` benchmark suite

## Run

```bash
cargo run --bin xmss -- --format human --message-size 64
```

JSON output:

```bash
cargo run --bin xmss -- --format json --message-size 64
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

The `xmss` benchmark binary uses the shared workspace CLI. The separate
`src/bin/xmss_bench.rs` helper keeps its own environment-based interface.
