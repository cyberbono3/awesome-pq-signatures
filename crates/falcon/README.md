# Falcon

Lattice-based signature scheme with small signatures.

## Library

[pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon)

## `src/main.rs` (`falcon-bench` binary)

`src/main.rs` is a single-run benchmark/report binary for Falcon-512. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p falcon --bin falcon-bench
```

Latest run result (captured on 2026-02-18 17:34:51 UTC):

```text
=== Falcon-512 Benchmark ===

--- Key Generation ---
Time to generate keys: 21.445666ms
Time to generate keys (ns): 21445666

--- Signing ---
Time to sign: 1.45825ms
Time to sign (ns): 1458250
Peak memory during signing: 815 bytes

--- Verification ---
Time to verify: 85.5us
Time to verify (ns): 85500
Peak memory during verification: 722 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 897 bytes
Secret key size: 1281 bytes
Signature size: 659 bytes
Signed message size: 722 bytes
```

## `benches/falcon_divan.rs` (Divan benchmark suite)

`benches/falcon_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p falcon --bench falcon_divan
```

Latest run result (captured on 2026-02-18 17:34:51 UTC):

```text
Falcon-512 sizes:
  Public key: 897 bytes
  Secret key: 1281 bytes
  Signature (message 32 bytes): 653 bytes
  Signature (message 256 bytes): 655 bytes
  Signature (message 1024 bytes): 657 bytes
  Signature (message 4096 bytes): 658 bytes

Falcon-512 peak heap usage:
  Message 32 bytes: sign=784 bytes, verify=695 bytes
  Message 256 bytes: sign=1008 bytes, verify=916 bytes
  Message 1024 bytes: sign=1776 bytes, verify=1679 bytes
  Message 4096 bytes: sign=4848 bytes, verify=4754 bytes

Divan timing summary (median):
  keygen: 5.264 ms
  sign(32): 151 us
  sign(256): 153.9 us
  sign(1024): 156.2 us
  sign(4096): 165.4 us
  verify(32): 21.61 us
  verify(256): 22.55 us
  verify(1024): 25.07 us
  verify(4096): 37.24 us
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
