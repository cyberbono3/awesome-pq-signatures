# LESS

Code-based post-quantum signature candidate (LESS).

## Overview

LESS (Linear Equivalence Signature Scheme) is a stateless code-based digital signature scheme. It is built on the hardness of the Linear Code Equivalence Problem, with multiple parameter sets targeting different security categories and tradeoffs between speed and signature size.

At a high level, the scheme exposes the familiar signature flow:
- generate a public/secret keypair
- sign an arbitrary message
- verify the signature against the public key

Unlike stateful hash-based schemes such as LMS or XMSS, LESS does not consume one-time leaves or require persistent signing state between signatures.

## Library

- [LESS specification](https://www.less-project.com/)
- [LESS implementation (C)](https://github.com/less-sig/LESS)

## Variant

This crate vendors the upstream NEON-optimized C implementation and builds the `CATEGORY=400, TARGET=102` parameter set as `LESS-400-102`.

For this variant, the upstream parameter header fixes:
- security category: `3` (CATEGORY 400)
- optimization target: `102`
- `N = 400`
- `K = 200`
- `NUM_KEYPAIRS = 4`
- `T = 102`
- `W = 61`

## Implementation Notes

This crate does not reimplement LESS in Rust. It wraps the upstream C99 NEON-optimized implementation through a thin FFI layer and compiles it from `build.rs`.

Important local choices:
- this workspace uses the NEON-optimized implementation, targeting Apple M-series processors
- the wrapper exposes the NIST-style byte API and maps it into Rust `LessKeyPair` and `LessSignature` types
- benchmark runs use deterministic RNG seeding inside the wrapper so repeated runs are reproducible
- signing and verification are serialized behind a mutex because the vendored C code uses shared RNG state through the shim

That makes the crate suitable for benchmarking and comparative inspection, but it is not yet a polished general-purpose Rust LESS library API.

## `src/main.rs` (`less` binary)

`src/main.rs` is a single-run benchmark/report binary for the selected LESS variant. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p less --bin less --release
```

## `benches/less_divan.rs` (Divan benchmark suite)

`benches/less_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

Run it with:

```bash
cargo bench -p less --bench less_divan
```

Observed size output from the latest `less_divan` run:
- `LESS-400-102`: `pk=105174`, `sk=48`
- `sig(32B)=4131`
- `sig(256B)=4131`
- `sig(1024B)=4131`
- `sig(4096B)=4131`

Observed peak heap usage from the latest `less_divan` run:
- `32B`: `sign=7982`, `verify=3883`
- `256B`: `sign=8302`, `verify=4427`
- `1024B`: `sign=8998`, `verify=5891`
- `4096B`: `sign=12142`, `verify=12107`

Median timings from `cargo bench -p less --bench less_divan` on `2026-03-26 09:39:49 UTC`:
- `keygen`: `2.657 ms`
- `sign`
  - `32B`: `118.2 ms`
  - `256B`: `115.2 ms`
  - `1024B`: `117.9 ms`
  - `4096B`: `117.7 ms`
- `verify`
  - `32B`: `116.7 ms`
  - `256B`: `117 ms`
  - `1024B`: `112.9 ms`
  - `4096B`: `116 ms`
