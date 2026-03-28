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
- `src/main.rs`: standard workspace benchmark binary (`--format human|json --message-size N`)
- `src/bin/xmssmt_bench.rs`: bench command used by `bench/run.sh`
- `benches/xmssmt_divan.rs`: `divan` benchmark suite

## Run

The `xmssmt` benchmark binary uses the shared workspace CLI contract and accepts
`--format human|json --message-size N`.

```bash
cargo run --bin xmssmt -- --format human --message-size 64
```

JSON output:

```bash
cargo run --bin xmssmt -- --format json --message-size 64
```

Representative local run:

```text
=== XMSSMT-SHA2_20/2_256 (RustCrypto xmss (pure Rust)) Benchmark ===

Key generation: 1.695662541 s
Signing:        3.332160416 s
Verification:   1.871667 ms
Public key:     68 bytes
Secret key:     135 bytes
Signature:      4963 bytes
```

Run the Divan benchmarks with:

```bash
cargo bench -p xmssmt-bench --bench xmssmt_divan
```

Representative local Divan result (bounded run with `--sample-count 10 --max-time 1`):

```text
Divan timing summary (median):
  keygen: 1.655 s
  sign(32): 4.762 s
  sign(1024): 4.858 s
  verify(32): 1.795 ms
  verify(1024): 1.803 ms
```

The separate
`src/bin/xmssmt_bench.rs` helper keeps its own environment-based interface.
