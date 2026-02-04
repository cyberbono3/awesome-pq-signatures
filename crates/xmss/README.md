# XMSS

Hash-based Merkle signature scheme (RFC 8391).

## Highlights

- Hash-based, post-quantum security relying on the underlying hash function.
- Stateful, single-tree construction built from WOTS+ one-time signatures.
- Tunable parameters (tree height, hash function) trade signature size vs. total signatures.
- Standardized in RFC 8391 with broad reference material.

## Pros

- Conservative security assumptions (hash function only).
- Compact public keys and simple verification structure.
- No per-signature randomness required (deterministic given state).

## Cons

- Stateful signing: the signer must track and advance the leaf index to avoid reuse.
- Hard limit on signatures per key pair (2^h leaves).
- Signature size and signing cost grow with tree height.

## Benchmarking strategy

Outline for consistent, reproducible measurements:

- Define scope: keygen (tree init), sign (state advances), verify.
- Select implementations: fix library + commit/tag; avoid mixed backends in one run.
- Control environment: pin CPU cores, isolate background load, fix governor/turbo policy.
- Build setup: record compiler version, optimization flags, and feature toggles.
- Workload matrix: cover representative message sizes and iterations; include warmups.
- Parameter sets: encode XMSS params (e.g., `XMSS-SHA2_10_256`).
- Measure: wall-clock latency and throughput; optionally memory, cache misses if available.
- Validate: check signature correctness and ensure state never reuses one-time keys.

Minimum metadata to record per run:

- CPU model, microcode, RAM, OS/kernel
- Compiler version + flags
- Library name + commit hash/tag
- Algorithm + parameter set
- Message sizes + number of iterations
- Whether turbo scaling was on/off
- RNG source

## Benchmarking harness

`bench/run.sh` collects metadata and writes JSON/CSV results. See `bench/results_schema.json`,
`bench/results_schema.csv`, `bench/example_results.json`, and `bench/example_results.csv`
for the output layout.

## Library

[xmss-rust](https://gitlab.zapb.de/crypto/xmss-rust)
