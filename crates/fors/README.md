# FORS

## Overview

This crate implements the Forest of Random Subsets (FORS) component used by SLH-DSA (Stateless Hash-based Digital Signature Algorithm), following the finalized NIST standard in [FIPS-205](https://csrc.nist.gov/pubs/fips/205/final). It is intended as a focused building block for SLH-DSA implementations rather than a standalone signature scheme.

## Signature Characteristics

- One-time, hash-based, stateless component inside SLH-DSA.
- Security relies on preimage resistance of the underlying hash functions.
- Signatures consist of selected secret values and authentication paths over small Merkle trees.
- Large signature sizes compared to lattice-based schemes; verification is hash-heavy.
- Not a standalone scheme; it is combined with other SLH-DSA components.

## Pros

- Conservative security assumptions (hash functions only).
- Stateless design avoids state management pitfalls of classic hash-based signatures.
- Simple construction and straightforward verification logic.

## Cons

- Large signatures and public keys compared to many alternatives.
- Slower signing and verification due to heavy hashing.
- Primarily useful as a building block rather than a general-purpose standalone scheme.

## Benchmarking Strategy

Use the benchmark runner to collect repeatable measurements and record metadata alongside results.

- Script: [`bench/run.sh`](bench/run.sh)
- Scope: key generation, signing, and verification for selected SLH-DSA parameter sets.
- Workload: keep message sizes fixed and prefer pre-hashed inputs to isolate FORS costs.
- Method: run warmups, multiple runs, and fixed iterations; report avg ns and throughput.
- Environment: capture compiler flags, RNG source, CPU/OS details, and library commit.
- Validation: use deterministic RNG to generate test vectors and compare across builds.
- Safety: enable buffer canaries or similar checks to detect out-of-bounds writes.
- Memory: track stack usage and code size separately from shared hash implementations.

Example:

```bash
BENCH_CMD='cargo run --release --bin fors_bench --' \
  PARAM_SETS=SLH-DSA-SHA2-128s MSG_SIZES=32 ITERATIONS=100 \
  WARMUP_RUNS=3 RUNS=5 OPERATIONS=keygen,sign,verify \
  crates/fors/bench/run.sh
```

## Library

[slh-dsa](https://crates.io/crates/slh-dsa)
