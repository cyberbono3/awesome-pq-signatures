# XMSSMT

Multi-tree XMSS variant for faster signing.

## Highlights

- Hash-based, post-quantum security relying on the underlying hash function.
- Multi-tree structure trades faster signing for more state and storage.
- Tunable parameters (total height, layers, hash function) balance size vs. speed.
- Standardized in RFC 8391 alongside XMSS.

## Pros

- Faster signing than XMSS for comparable security levels (smaller per-tree height).
- Conservative security assumptions (hash function only).
- No per-signature randomness required (deterministic given state).

## Cons

- Stateful signing: signer must track and advance indices across layers.
- Larger public keys and signatures than XMSS for similar security.
- More complex parameter selection and implementation.

## Benchmarking strategy

Outline for consistent, reproducible measurements:

- Define scope: keygen (multi-tree init), sign (state advances), verify.
- Select implementations: fix library + commit/tag; avoid mixed backends in one run.
- Control environment: pin CPU cores, isolate background load, fix governor/turbo policy.
- Build setup: record compiler version, optimization flags, and feature toggles.
- Workload matrix: cover representative message sizes and iterations; include warmups.
- Parameter sets: encode XMSSMT params (e.g., `XMSSMT-SHA2_20/2_256`).
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

[xmss-rs](https://github.com/thomwiggers/xmss-rs)
