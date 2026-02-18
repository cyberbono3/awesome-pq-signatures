# SPHINCS+ (SLH-DSA)

Stateless hash-based signature benchmarking crate.

## Library

[pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus)

## `src/main.rs` (`sphincs-plus-bench` binary)

`src/main.rs` is a single-run benchmark/report binary for `SPHINCS+-SHAKE-128f-simple`. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p sphincs_plus --bin sphincs-plus-bench
```

Latest run result (captured on 2026-02-18 18:56:27 UTC):

```text
=== SPHINCS+-SHAKE-128f-simple Benchmark ===

--- Key Generation ---
Time to generate keys: 7.854833ms
Time to generate keys (ns): 7854833

--- Signing ---
Time to sign: 193.986458ms
Time to sign (ns): 193986458
Peak memory during signing: 17153 bytes

--- Verification ---
Time to verify: 10.147625ms
Time to verify (ns): 10147625
Peak memory during verification: 17153 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 32 bytes
Secret key size: 64 bytes
Signature size: 17088 bytes
Signed message size: 17153 bytes
```

## `benches/sphincs_plus_divan.rs` (Divan benchmark suite)

`benches/sphincs_plus_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p sphincs_plus --bench sphincs_plus_divan
```

Latest run result (captured on 2026-02-18 18:56:27 UTC):

```text
SPHINCS+-SHAKE-128f-simple sizes:
  Public key: 32 bytes
  Secret key: 64 bytes
  Signature (message 32 bytes): 17088 bytes
  Signature (message 256 bytes): 17088 bytes
  Signature (message 1024 bytes): 17088 bytes
  Signature (message 4096 bytes): 17088 bytes

SPHINCS+-SHAKE-128f-simple peak heap usage:
  Message 32 bytes: sign=17120 bytes, verify=17120 bytes
  Message 256 bytes: sign=17344 bytes, verify=17344 bytes
  Message 1024 bytes: sign=18112 bytes, verify=18112 bytes
  Message 4096 bytes: sign=21184 bytes, verify=21184 bytes

Divan timing summary (median):
  keygen: 1.498 ms
  sign(32): 24.98 ms
  sign(256): 24.48 ms
  sign(1024): 24.42 ms
  sign(4096): 24.47 ms
  verify(32): 1.507 ms
  verify(256): 1.48 ms
  verify(1024): 1.427 ms
  verify(4096): 1.515 ms
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
