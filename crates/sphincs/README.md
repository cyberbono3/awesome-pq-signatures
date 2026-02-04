# SPHINCS (original)

Predecessor to SPHINCS+ with older parameters.

## Highlights

- Stateless hash-based signature scheme (no stateful key tracking).
- Original SPHINCS construction predating SPHINCS+.
- Conservative security assumptions based on hash functions.

## Pros

- Stateless usage simplifies operational safety.
- Hash-only assumptions with broad portability.

## Cons

- Larger signatures and slower performance than SPHINCS+.
- Legacy parameter sets; not the modern standardized choice.

## SPHINCS vs SPHINCS+

- SPHINCS is the original design; SPHINCS+ is the improved, standardized successor.
- SPHINCS+ offers better performance and signature-size tradeoffs for comparable security.
- New deployments should generally prefer SPHINCS+ unless compatibility requires SPHINCS.

## Benchmarking strategy

Outline for consistent, reproducible measurements:

- Define scope: keygen, sign, verify, and sizes for each SPHINCS parameter set.
- Select implementations: fix library + commit/tag; avoid mixed backends in one run.
- Control environment: pin CPU cores, isolate background load, fix governor/turbo policy.
- Build setup: record compiler version, optimization flags, and feature toggles.
- Workload matrix: cover representative message sizes and iterations; include warmups.
- Measure: wall-clock latency and throughput; optionally memory, cache misses if available.
- Validate: check signature correctness and stability across repeats.

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

[gravity-rs](https://github.com/gendx/gravity-rs)
