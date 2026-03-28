# Dilithium

Lattice-based signature scheme based on ML-DSA.

## Library

[ml-dsa](https://crates.io/crates/ml-dsa)

## `src/main.rs` (`dilithium` binary)

`src/main.rs` is the standard workspace benchmark binary for ML-DSA-65. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

The binary uses the shared `pq_bench` workspace contract and accepts
`--format human|json --message-size N`.

Run it with:

```bash
cargo run -p dilithium --bin dilithium -- --format human --message-size 64
```

JSON output:

```bash
cargo run -p dilithium --bin dilithium -- --format json --message-size 64
```

Representative local run:

```text
=== Dilithium (ML-DSA-65) Benchmark ===

Key generation: 19.49975 ms
Signing:        33.311834 ms
Verification:   2.323 ms
Public key:     1952 bytes
Secret key:     4032 bytes
Signature:      3309 bytes
```

## `benches/dilithium_divan.rs` (Divan benchmark suite)

`benches/dilithium_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches, using the shared `pq_bench` bench helpers.

Run it with:

```bash
cargo bench -p dilithium --bench dilithium_divan
```

Representative local Divan run:

```text
ML-DSA-65 sizes:
  Public key: 1952 bytes
  Secret key: 4032 bytes
  Signature (message 32 bytes): 3309 bytes
  Signature (message 256 bytes): 3309 bytes
  Signature (message 1024 bytes): 3309 bytes
  Signature (message 4096 bytes): 3309 bytes

ML-DSA-65 peak heap usage:
  Message 32 bytes: sign=0 bytes, verify=0 bytes
  Message 256 bytes: sign=0 bytes, verify=0 bytes
  Message 1024 bytes: sign=0 bytes, verify=0 bytes
  Message 4096 bytes: sign=0 bytes, verify=0 bytes

Divan timing summary (median):
  keygen: 201.3 us
  sign(32): 569.5 us
  sign(256): 100.7 us
  sign(1024): 102.2 us
  sign(4096): 342.1 us
  verify(32): 44.58 us
  verify(256): 44.91 us
  verify(1024): 46.41 us
  verify(4096): 51.04 us
```

Note: timings and allocation figures vary by machine, compiler version, and system load.
