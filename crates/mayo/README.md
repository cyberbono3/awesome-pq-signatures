# MAYO

**MAYO** is a **multivariate post-quantum digital signature scheme** built from structured systems of multivariate quadratic equations over finite fields. Unlike stateful hash-based schemes such as LMS or HSS, MAYO is **stateless**: signing does not consume one-time leaves or require persistent key-state updates between signatures. Its design aims to offer practical post-quantum signatures from the hardness of solving structured equation systems while keeping key and signature handling straightforward for repeated signing workloads.

## Library

- Rust: [pq-mayo](https://crates.io/crates/pq-mayo)
- Current benchmark parameter set from `bench_config.toml`: `MAYO-3`

## `src/main.rs` (`mayo` binary)

`src/main.rs` is a single-run benchmark/report binary for MAYO. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p mayo --release --bin mayo
```

Representative local result from `cargo run -p mayo --release --bin mayo`
(captured on 2026-03-26 09:39:49 UTC):

```text
=== MAYO (MAYO-3) Benchmark ===

--- Key Generation ---
Time to generate keys: 2.523ms
Time to generate keys (ns): 2523000

--- Signing ---
Time to sign: 5.806333ms
Time to sign (ns): 5806333
Peak memory during signing: 2168415 bytes

--- Verification ---
Time to verify: 2.104584ms
Time to verify (ns): 2104584
Peak memory during verification: 1745820 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 2986 bytes
Secret key size: 32 bytes
Signature size: 681 bytes
Signed message size: 713 bytes
```

## `benches/mayo_divan.rs` (Divan benchmark suite)

`benches/mayo_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p mayo --bench mayo_divan
```

Latest observed local run (`cargo bench -p mayo --bench mayo_divan`, captured on 2026-03-26 09:39:49 UTC):

```text
MAYO-3 sizes:
  Public key: 2986 bytes
  Secret key: 32 bytes
  Signature (message 32 bytes): 681 bytes
  Signature (message 256 bytes): 681 bytes
  Signature (message 1024 bytes): 681 bytes
  Signature (message 4096 bytes): 681 bytes
MAYO-3 peak heap usage:
  Message 32 bytes: sign=2168079 bytes, verify=1745820 bytes
  Message 256 bytes: sign=2168079 bytes, verify=1745820 bytes
  Message 1024 bytes: sign=2168079 bytes, verify=1745820 bytes
  Message 4096 bytes: sign=2168079 bytes, verify=1745820 bytes

Divan timing summary (median):
  keygen: 2.402 ms
  sign(32): 5.663 ms
  sign(256): 5.595 ms
  sign(1024): 5.619 ms
  sign(4096): 5.623 ms
  verify(32): 2.092 ms
  verify(256): 2.069 ms
  verify(1024): 2.043 ms
  verify(4096): 2.108 ms
```
