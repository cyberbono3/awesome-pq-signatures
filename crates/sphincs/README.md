# SPHINCS

Hash-based signature benchmarking crate.

## Library

Primary backend: [gravity-rs](https://github.com/gendx/gravity-rs) (`gravity` crate, `GravitySmall`).

Architecture note:
- `x86` / `x86_64`: uses `gravity-rs`
- non-`x86` architectures (for example Apple Silicon `arm64`): falls back to `pqcrypto-sphincsplus` because current `gravity-rs` SIMD implementation is x86/x86_64-only

## `src/main.rs` (`sphincs-bench` binary)

`src/main.rs` is a single-run benchmark/report binary. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p sphincs --bin sphincs-bench
```

Latest run result (captured on 2026-02-18 18:11:12 UTC):

```text
=== SPHINCS+-SHAKE-128f-simple Benchmark ===

Backend: pqcrypto-sphincsplus (gravity-rs unavailable on this architecture)

--- Key Generation ---
Time to generate keys: 7.98725ms
Time to generate keys (ns): 7987250

--- Signing ---
Time to sign: 185.4075ms
Time to sign (ns): 185407500
Peak memory during signing: 34304 bytes

--- Verification ---
Time to verify: 10.353208ms
Time to verify (ns): 10353208
Peak memory during verification: 34304 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 32 bytes
Secret key size: 64 bytes
Signature size: 17152 bytes
Signed message size: 17216 bytes
```

## `benches/sphincs_divan.rs` (Divan benchmark suite)

`benches/sphincs_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p sphincs --bench sphincs_divan
```

Latest run result (captured on 2026-02-18 18:11:12 UTC):

```text
SPHINCS+-SHAKE-128f-simple sizes:
  Public key: 32 bytes
  Secret key: 64 bytes
  Signature (message 32 bytes): 17120 bytes
  Signature (message 256 bytes): 17344 bytes
  Signature (message 1024 bytes): 18112 bytes
  Signature (message 4096 bytes): 21184 bytes

SPHINCS+-SHAKE-128f-simple peak heap usage:
  Message 32 bytes: sign=34240 bytes, verify=34240 bytes
  Message 256 bytes: sign=34688 bytes, verify=34688 bytes
  Message 1024 bytes: sign=36224 bytes, verify=36224 bytes
  Message 4096 bytes: sign=42368 bytes, verify=42368 bytes

Divan timing summary (median):
  keygen: 1.041 ms
  sign(32): 24.89 ms
  sign(256): 24.81 ms
  sign(1024): 25.02 ms
  sign(4096): 24.96 ms
  verify(32): 1.495 ms
  verify(256): 1.518 ms
  verify(1024): 1.535 ms
  verify(4096): 1.477 ms
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
