# Dilithium

Lattice-based signature scheme based on ML-DSA.

## Library

[ml-dsa](https://crates.io/crates/ml-dsa)

## `src/main.rs` (`dilithium` binary)

`src/main.rs` is a single-run benchmark/report binary for ML-DSA-44. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p dilithium --bin dilithium
```

Latest run result (captured on 2026-03-26 07:51:41 UTC):

```text
=== Dilithium (ML-DSA-44) Benchmark ===

--- Key Generation ---
Time to generate keys: 157.209us
Time to generate keys (ns): 157209

--- Signing ---
Time to sign: 612.208us
Time to sign (ns): 612208
Peak memory during signing: 0 bytes

--- Verification ---
Time to verify: 34us
Time to verify (ns): 34000
Peak memory during verification: 0 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 1312 bytes
Secret key size: 2560 bytes
Signature size: 2420 bytes
Signed message size: 2452 bytes
```

## `benches/dilithium_divan.rs` (Divan benchmark suite)

`benches/dilithium_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p dilithium --bench dilithium_divan
```

Latest run result (captured on 2026-03-26 07:51:41 UTC):

```text
ML-DSA-44 sizes:
  Public key: 1312 bytes
  Secret key: 2560 bytes
  Signature (message 32 bytes): 2420 bytes
  Signature (message 256 bytes): 2420 bytes
  Signature (message 1024 bytes): 2420 bytes
  Signature (message 4096 bytes): 2420 bytes

ML-DSA-44 peak heap usage:
  Message 32 bytes: sign=0 bytes, verify=0 bytes
  Message 256 bytes: sign=0 bytes, verify=0 bytes
  Message 1024 bytes: sign=0 bytes, verify=0 bytes
  Message 4096 bytes: sign=0 bytes, verify=0 bytes

Divan timing summary (median):
  keygen: 124.4 us
  sign(32): 425.6 us
  sign(256): 403.2 us
  sign(1024): 198.9 us
  sign(4096): 519.9 us
  verify(32): 33.54 us
  verify(256): 33.49 us
  verify(1024): 35.16 us
  verify(4096): 38.14 us
```

Note: benchmark timings and allocation metrics vary by machine, compiler version, and system load.

## Benchmark Environment

The benchmark results above were recorded on:

- machine: MacBook Pro (`MacBookPro18,1`)
- chip: Apple M1 Pro (10 cores: 8 performance + 2 efficiency)
- memory: 16 GB
- OS: macOS 26.1 (`25B78`)
- kernel/arch: Darwin 25.1.0, `arm64`
- rust toolchain: `rustc 1.87.0-nightly (f4a216d28 2025-03-02)`
- cargo: `cargo 1.87.0-nightly (2622e844b 2025-02-28)`
