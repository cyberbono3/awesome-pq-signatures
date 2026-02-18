# SPHINCS

Hash-based signature benchmarking crate.

## Library

Primary backend: [gravity-rs](https://github.com/gendx/gravity-rs) (`gravity` crate, `GravitySmall`).

Architecture note:
- `x86` / `x86_64`: supported with `gravity-rs`
- non-`x86` architectures (for example Apple Silicon `arm64`): not supported in this crate configuration
- On non-`x86` architectures, `backend_name()` reports unsupported and the crate panics only when Gravity operations (`keypair`, `sign`, `verify`) are called.

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
=== Gravity-SPHINCS (Small) Benchmark ===

Backend: gravity-rs

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
Signature size: <x86/x86_64 dependent runtime value>
Signed message size: <x86/x86_64 dependent runtime value>
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
Gravity-SPHINCS (Small) sizes:
  Public key: 32 bytes
  Secret key: 64 bytes
  Signature (message 32 bytes): <x86/x86_64 dependent runtime value>
  Signature (message 256 bytes): <x86/x86_64 dependent runtime value>
  Signature (message 1024 bytes): <x86/x86_64 dependent runtime value>
  Signature (message 4096 bytes): <x86/x86_64 dependent runtime value>

Gravity-SPHINCS (Small) peak heap usage:
  Message 32 bytes: sign=<x86/x86_64 dependent runtime value>, verify=<x86/x86_64 dependent runtime value>
  Message 256 bytes: sign=<x86/x86_64 dependent runtime value>, verify=<x86/x86_64 dependent runtime value>
  Message 1024 bytes: sign=<x86/x86_64 dependent runtime value>, verify=<x86/x86_64 dependent runtime value>
  Message 4096 bytes: sign=<x86/x86_64 dependent runtime value>, verify=<x86/x86_64 dependent runtime value>

Divan timing summary (median):
  keygen: <x86/x86_64 dependent runtime value>
  sign(32): <x86/x86_64 dependent runtime value>
  sign(256): <x86/x86_64 dependent runtime value>
  sign(1024): <x86/x86_64 dependent runtime value>
  sign(4096): <x86/x86_64 dependent runtime value>
  verify(32): <x86/x86_64 dependent runtime value>
  verify(256): <x86/x86_64 dependent runtime value>
  verify(1024): <x86/x86_64 dependent runtime value>
  verify(4096): <x86/x86_64 dependent runtime value>
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
