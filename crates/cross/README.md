# CROSS

Code-based post-quantum signature candidate (CROSS).

## Overview

CROSS is a stateless code-based digital signature scheme. The upstream project describes it as an asymmetric signature construction built around the hardness of the `RSDP` and `RSDP(G)` problem families, with multiple parameter sets targeting different security categories and tradeoffs between speed and signature size.

At a high level, the scheme exposes the familiar signature flow:
- generate a public/secret keypair
- sign an arbitrary message
- verify the signature against the public key

Unlike stateful hash-based schemes such as LMS or XMSS, CROSS does not consume one-time leaves or require persistent signing state between signatures.

## Library

- [cross-crypto.com](https://www.cross-crypto.com/cross.html)
- [CROSS reference implementation (C)](https://github.com/CROSS-signature/CROSS-implementation)

## Variant

This crate vendors the upstream portable C reference implementation and builds the `CATEGORY_3 + BALANCED + RSDPG` parameter set as `CROSS-RSDPG-192-BALANCED`.

For this variant, the upstream parameter header fixes:
- security margin: `192`
- problem family: `RSDPG`
- optimization target: `BALANCED`
- `N = 79`
- `K = 48`
- `M = 40`
- `T = 268`
- `W = 196`

In practice, this gives this workspace build very small keys and a large signature:
- public key: `83` bytes
- secret key: `48` bytes
- signature: `22464` bytes

Those sizes come from the compiled reference implementation used by this crate.

## Implementation Notes

This crate does not reimplement CROSS in Rust. It wraps the upstream C11 reference implementation through a thin FFI layer and compiles it from [`build.rs`](./build.rs).

Important local choices:
- this workspace uses the portable reference implementation, not the upstream AVX2-optimized implementation
- the wrapper exposes the NIST-style byte API and maps it into Rust `CrossKeyPair` and `CrossSignature` types
- benchmark runs use deterministic RNG seeding inside the wrapper so repeated runs are reproducible
- signing and verification are serialized behind a mutex because the vendored C code uses shared RNG state through the shim

That makes the crate suitable for benchmarking and comparative inspection, but it is not yet a polished general-purpose Rust CROSS library API.

## `src/main.rs` (`cross` binary)

`src/main.rs` is a single-run benchmark/report binary for the selected CROSS variant. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p cross --bin cross
```

A recent local run produced:

```text
=== CROSS (CROSS-RSDPG-192-BALANCED) Benchmark ===

Key generation: 115.208 us
Signing:        7.2055 ms
Verification:   4.929625 ms
Public key:     83 bytes
Secret key:     48 bytes
Signature:      22464 bytes
```

## `benches/cross_divan.rs` (Divan benchmark suite)

`benches/cross_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p cross --bench cross_divan
```

## Files

- `src/lib.rs`: Rust wrapper around the vendored C reference implementation
- `src/main.rs`: single-shot benchmark/report binary
- `benches/cross_divan.rs`: Divan microbenchmarks
- `build.rs`: C build configuration for the selected CROSS variant
- `vendor/reference/`: vendored upstream portable reference implementation
