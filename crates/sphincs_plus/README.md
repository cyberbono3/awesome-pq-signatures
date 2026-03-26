# SPHINCS+ (SLH-DSA)

Stateless hash-based signature benchmarking crate.

## Library

[pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus)

## `src/main.rs` (`sphincs-plus-bench` binary)

`src/main.rs` is a single-run benchmark/report binary for `SPHINCS+-SHAKE-192f-simple`. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p sphincs_plus --bin sphincs-plus-bench
```

Latest run result (captured on 2026-03-26 09:39:49 UTC):

```text
=== SPHINCS+-SHAKE-192f-simple Benchmark ===

--- Key Generation ---
Time to generate keys: 2.194917ms
Time to generate keys (ns): 2194917

--- Signing ---
Time to sign: 42.58625ms
Time to sign (ns): 42586250
Peak memory during signing: 35696 bytes

--- Verification ---
Time to verify: 3.434791ms
Time to verify (ns): 3434791
Peak memory during verification: 35696 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 48 bytes
Secret key size: 96 bytes
Signature size: 35664 bytes
Signed message size: 35696 bytes
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

Latest run result (captured on 2026-03-26 09:39:49 UTC):

```text
SPHINCS+-SHAKE-192f-simple sizes:
  Public key: 48 bytes
  Secret key: 96 bytes
  Signature (message 32 bytes): 35664 bytes
  Signature (message 256 bytes): 35664 bytes
  Signature (message 1024 bytes): 35664 bytes
  Signature (message 4096 bytes): 35664 bytes

SPHINCS+-SHAKE-192f-simple peak heap usage:
  Message 32 bytes: sign=35696 bytes, verify=35696 bytes
  Message 256 bytes: sign=35920 bytes, verify=35920 bytes
  Message 1024 bytes: sign=36688 bytes, verify=36688 bytes
  Message 4096 bytes: sign=39760 bytes, verify=39760 bytes

Divan timing summary (median):
  keygen: 1.681 ms
  sign(32): 45.23 ms
  sign(256): 41.47 ms
  sign(1024): 41.59 ms
  sign(4096): 41.65 ms
  verify(32): 2.256 ms
  verify(256): 2.777 ms
  verify(1024): 2.165 ms
  verify(4096): 2.326 ms
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
