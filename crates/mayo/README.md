# MAYO

**MAYO** is a **multivariate post-quantum digital signature scheme** built from structured systems of multivariate quadratic equations over finite fields. Unlike stateful hash-based schemes such as LMS or HSS, MAYO is **stateless**: signing does not consume one-time leaves or require persistent key-state updates between signatures. Its design aims to offer practical post-quantum signatures from the hardness of solving structured equation systems while keeping key and signature handling straightforward for repeated signing workloads.

## Library

- Rust: [pq-mayo](https://crates.io/crates/pq-mayo)
- Default benchmark parameter set: `Mayo1`

## `src/main.rs` (`mayo` binary)

`src/main.rs` is the standard workspace benchmark binary for MAYO. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p mayo --bin mayo -- --format human --message-size 64
```

JSON output:

```bash
cargo run -p mayo --bin mayo -- --format json --message-size 64
```

Representative local result from `cargo run -p mayo --bin mayo -- --format human --message-size 64`:
timings below use the median of 5 local release runs; size and memory fields are from a representative release run.

```text
=== MAYO (MAYO) Benchmark ===

--- Key Generation ---
Time to generate keys: 948.458µs
Time to generate keys (ns): 948458

--- Signing ---
Time to sign: 2.2935ms
Time to sign (ns): 2293500
Peak memory during signing: 970287 bytes

--- Verification ---
Time to verify: 1.243709ms
Time to verify (ns): 1243709
Peak memory during verification: 803629 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 1420 bytes
Secret key size: 24 bytes
Signature size: 454 bytes
Signed message size: 515 bytes
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

Latest observed local run (`cargo bench -p mayo --bench mayo_divan`):

```text
MAYO sizes:
  Public key: 1420 bytes
  Secret key: 24 bytes
  Signature (message 32 bytes): 454 bytes
  Signature (message 256 bytes): 454 bytes
  Signature (message 1024 bytes): 454 bytes
  Signature (message 4096 bytes): 454 bytes
MAYO peak heap usage:
  Message 32 bytes: sign=969951 bytes, verify=803629 bytes
  Message 256 bytes: sign=969951 bytes, verify=803629 bytes
  Message 1024 bytes: sign=969951 bytes, verify=803629 bytes
  Message 4096 bytes: sign=969951 bytes, verify=803629 bytes

Divan timing summary (median):
  keygen: 844.4 µs
  sign(32): 2.04 ms
  sign(256): 2.042 ms
  sign(1024): 2.045 ms
  sign(4096): 2.052 ms
  verify(32): 763.8 µs
  verify(256): 761.9 µs
  verify(1024): 762.6 µs
  verify(4096): 765.9 µs
```
