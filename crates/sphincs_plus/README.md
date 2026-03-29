# SPHINCS+ (SLH-DSA)

Stateless hash-based signature benchmarking crate.

## Library

[pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus)

## `src/main.rs` (`sphincs-plus-bench` binary)

`src/main.rs` is the standard workspace benchmark binary for `SPHINCS+-SHAKE-128f-simple`. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

The binary uses the shared `pq_bench` workspace contract and accepts
`--format human|json --message-size N`.

Run it with:

```bash
cargo run -p sphincs_plus --bin sphincs-plus-bench -- --format human --message-size 64
```

JSON output:

```bash
cargo run -p sphincs_plus --bin sphincs-plus-bench -- --format json --message-size 64
```

Representative local run:

```text
=== SPHINCS+-SHAKE-128f-simple Benchmark ===

Key generation: 7.854833 ms
Signing:        193.986458 ms
Verification:   10.147625 ms
Public key:     32 bytes
Secret key:     64 bytes
Signature:      17088 bytes
```

## `benches/sphincs_plus_divan.rs` (Divan benchmark suite)

`benches/sphincs_plus_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches, using the shared `pq_bench` bench helpers.

Run it with:

```bash
cargo bench -p sphincs_plus --bench sphincs_plus_divan
```

Representative local Divan run:

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

Note: timings and allocation figures vary by machine, compiler version, and system load.
