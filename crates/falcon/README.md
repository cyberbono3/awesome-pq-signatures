# Falcon

Lattice-based signature scheme with small signatures.

## Library

[pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon)

## `src/main.rs` (`falcon-bench` binary)

`src/main.rs` is the standard workspace benchmark binary for Falcon-512. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

The binary uses the shared `pq_bench` workspace contract and accepts
`--format human|json --message-size N`.

Run it with:

```bash
cargo run -p falcon --bin falcon-bench -- --format human --message-size 64
```

JSON output:

```bash
cargo run -p falcon --bin falcon-bench -- --format json --message-size 64
```

Representative local run:

```text
=== Falcon-512 Benchmark ===

Key generation: 21.445666 ms
Signing:        1.45825 ms
Verification:   85.5 us
Public key:     897 bytes
Secret key:     1281 bytes
Signature:      659 bytes
```

## `benches/falcon_divan.rs` (Divan benchmark suite)

`benches/falcon_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches, using the shared `pq_bench` bench helpers.

Run it with:

```bash
cargo bench -p falcon --bench falcon_divan
```

Representative local Divan run:

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

Note: timings and allocation figures vary by machine, compiler version, and system load.
