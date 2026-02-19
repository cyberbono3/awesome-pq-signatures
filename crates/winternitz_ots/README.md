# Winternitz OTS (W-OTS)

One-time hash-based signature with Winternitz chaining.

## Library

[winternitz-ots](https://crates.io/crates/winternitz-ots)

## `src/main.rs` (`winternitz_ots` binary)

`src/main.rs` is a single-run benchmark/report binary for W-OTS (`w=16`, `n=32`, Blake2b backend). It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p winternitz_ots --release --offline --bin winternitz_ots
```

Latest run result (captured on 2026-02-19 16:48:55 UTC):

```text
=== Winternitz OTS (W-OTS) Benchmark ===

Backend: winternitz-ots-0.3.0
Param set: w=16,n=32,hash=blake2b

--- Key Generation ---
Time to generate keys: 299.375µs
Time to generate keys (ns): 299375

--- Signing ---
Time to sign: 109.125µs
Time to sign (ns): 109125
Peak memory during signing: 13960 bytes

--- Verification ---
Time to verify: 119.458µs
Time to verify (ns): 119458
Peak memory during verification: 960 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 2144 bytes
Secret key size: 2144 bytes
Signature size: 2144 bytes
Signed digest input size: 32 bytes
Message size: 71 bytes
```

## `benches/winternitz_ots_divan.rs` (Divan benchmark suite)

`benches/winternitz_ots_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p winternitz_ots --bench winternitz_ots_divan --offline
```

Latest run result (captured on 2026-02-19 16:48:55 UTC):

```text
Winternitz OTS (W-OTS) sizes:
  Backend: winternitz-ots-0.3.0
  Param set: w=16,n=32,hash=blake2b
  Public key: 2144 bytes
  Secret key: 2144 bytes
  Signature (message 32 bytes): 2144 bytes
  Signature (message 256 bytes): 2144 bytes
  Signature (message 1024 bytes): 2144 bytes
  Signature (message 4096 bytes): 2144 bytes

Winternitz OTS (W-OTS) peak heap usage:
  Message 32 bytes: sign=28680 bytes, verify=960 bytes
  Message 256 bytes: sign=28680 bytes, verify=960 bytes
  Message 1024 bytes: sign=28680 bytes, verify=960 bytes
  Message 4096 bytes: sign=28680 bytes, verify=960 bytes

Divan timing summary (median):
  keygen: 248.4 us
  sign(32): 349.4 us
  sign(256): 343.9 us
  sign(1024): 343.6 us
  sign(4096): 345.1 us
  verify(32): 93.65 us
  verify(256): 98.05 us
  verify(1024): 101.4 us
  verify(4096): 98.74 us
```

Note: benchmark timings and allocation metrics vary by machine, compiler version, and system load.
