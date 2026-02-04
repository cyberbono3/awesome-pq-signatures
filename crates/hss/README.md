# HSS

Hierarchical LMS for large key hierarchies.

## Highlights

- Hash-based, post-quantum security assuming the underlying hash function.
- Extends LMS/LM-OTS (RFC 8554) by stacking LMS trees to support many signatures.
- Stateful signing: the signer must track and advance indices to avoid key reuse.
- Verification checks an LMS signature per hierarchy level plus authentication paths.

## Benchmarking strategy

Outline for consistent, reproducible measurements:

- Define scope: keygen (full hierarchy), sign (state advances), verify.
- Select implementations: fix library + commit/tag; avoid mixed backends in one run.
- Control environment: pin CPU cores, isolate background load, fix governor/turbo policy.
- Build setup: record compiler version, optimization flags, and feature toggles.
- Workload matrix: cover representative message sizes and iterations; include warmups.
- Parameter sets: encode HSS levels plus LMS + LM-OTS types per level.
- Measure: wall-clock latency and throughput; optionally memory, cache misses if available.
- Validate: check signature correctness and ensure state never reuses LMS/LM-OTS keys.

Minimum metadata to record per run:

- CPU model, microcode, RAM, OS/kernel
- Compiler version + flags
- Library name + commit hash/tag
- Algorithm + parameter set (levels + LMS/LM-OTS)
- Message sizes + number of iterations
- Whether turbo scaling was on/off
- RNG source

## Benchmarking harness

`bench/run.sh` collects metadata and writes JSON/CSV results. See `bench/results_schema.json`,
`bench/results_schema.csv`, `bench/example_results.json`, and `bench/example_results.csv`
for the output layout.

## Library

C: [cisco/hash-sigs](https://github.com/cisco/hash-sigs)
