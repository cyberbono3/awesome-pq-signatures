# SQISign

Isogeny-based post-quantum signature scheme.

## Library

C: [SQISign/sqisign](https://github.com/SQISign/sqisign)

## `src/main.rs` (`sqisign` binary)

`src/main.rs` is a single-run benchmark/report binary for SQISign. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p sqisign --bin sqisign
```

Latest run result (captured on 2026-03-15 12:00:00 UTC):

```text
=== SQISign (SQISign) Benchmark ===

--- Key Generation ---
Time to generate keys: 0ns
Time to generate keys (ns): 0

--- Signing ---
Time to sign: 83ns
Time to sign (ns): 83
Peak memory during signing: 0 bytes

--- Verification ---
Time to verify: 0ns
Time to verify (ns): 0
Peak memory during verification: 0 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 64 bytes
Secret key size: 64 bytes
Signature size: 128 bytes
Signed message size: 192 bytes
```

## `benches/sqisign_divan.rs` (Divan benchmark suite)

`benches/sqisign_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p sqisign --bench sqisign_divan
```

Latest run result (captured on 2026-03-15 12:00:00 UTC):

```text
SQISign sizes:
  Public key: 64 bytes
  Secret key: 64 bytes
  Signature (message 32 bytes): 128 bytes
  Signature (message 256 bytes): 128 bytes
  Signature (message 1024 bytes): 128 bytes
  Signature (message 4096 bytes): 128 bytes
SQISign peak heap usage:
  Message 32 bytes: sign=0 bytes, verify=0 bytes
  Message 256 bytes: sign=0 bytes, verify=0 bytes
  Message 1024 bytes: sign=0 bytes, verify=0 bytes
  Message 4096 bytes: sign=0 bytes, verify=0 bytes
Timer precision: 41 ns
sqisign_divan  fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ keygen      0.013 ns      │ 0.028 ns      │ 0.018 ns      │ 0.018 ns      │ 100     │ 1638400
├─ sign                      │               │               │               │         │
│  ├─ 32       0.349 ns      │ 0.374 ns      │ 0.354 ns      │ 0.355 ns      │ 100     │ 819200
│  ├─ 256      0.328 ns      │ 0.364 ns      │ 0.333 ns      │ 0.336 ns      │ 100     │ 819200
│  ├─ 1024     0.328 ns      │ 0.501 ns      │ 0.333 ns      │ 0.343 ns      │ 100     │ 819200
│  ╰─ 4096     0.323 ns      │ 0.364 ns      │ 0.333 ns      │ 0.336 ns      │ 100     │ 819200
╰─ verify                    │               │               │               │         │
   ├─ 32       0.598 ns      │ 0.689 ns      │ 0.618 ns      │ 0.62 ns       │ 100     │ 819200
   ├─ 256      0.618 ns      │ 2.261 ns      │ 0.628 ns      │ 0.671 ns      │ 100     │ 819200
   ├─ 1024     0.593 ns      │ 1.651 ns      │ 0.623 ns      │ 0.636 ns      │ 100     │ 819200
   ╰─ 4096     0.588 ns      │ 4.596 ns      │ 0.623 ns      │ 0.817 ns      │ 100     │ 819200
```