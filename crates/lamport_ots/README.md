# Lamport one-time signature (OTS)

## Overview

Lamport OTS is a one-time, hash-based signature scheme that uses pairs of random secrets per message bit and publishes their hashes as the public key. Signing reveals one secret from each pair, and verification hashes the revealed values to match the public key. It is simple, conservative, and intended for one-time use only.

## Signature Characteristics

- One-time, hash-based signature built from many random secrets.
- Security relies only on preimage resistance of the hash function.
- Very large signatures and public keys relative to modern lattice schemes.
- Fast verification and signing dominated by hashing operations.

## Pros

- Minimal and conservative security assumptions (hash functions only).
- Simple construction and straightforward verification logic.
- Easy to implement and audit.

## Cons

- One-time use; reusing a keypair leaks information about the secret key.
- Large signature and public key sizes.
- Inefficient for bandwidth-constrained or storage-constrained environments.

## Benchmarking Strategy

Use the benchmark runner to gather repeatable performance and metadata for Lamport OTS.

- Script: [`bench/run.sh`](bench/run.sh)
- Scope: key generation, signing, and verification (one-time usage assumptions).
- Workload: keep message sizes fixed; prefer pre-hashed inputs to isolate core costs.
- Method: warmups + multiple runs with fixed iterations; report avg ns and throughput.
- Environment: record compiler flags, RNG source, CPU/OS details, and library commit.
- Validation: enable deterministic RNG for reproducible test vectors across builds.
- Safety: use canary checks for buffers and optional stack usage measurement.
- Memory: track code size separately from shared hash implementations.

Example:

```bash
BENCH_CMD='cargo run --release --bin lamport_ots_bench --' \
  PARAM_SETS=Lamport-OTS-256 MSG_SIZES=32 ITERATIONS=100 \
  WARMUP_RUNS=3 RUNS=5 OPERATIONS=keygen,sign,verify \
  crates/lamport_ots/bench/run.sh
```

## Library

[lamport_signature](https://crates.io/crates/lamport_signature)
