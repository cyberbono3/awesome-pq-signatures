# LM-OTS

Leighton-Micali one-time signature used by LMS.

## Benchmarking strategy

Outline for consistent, reproducible measurements:

- Define scope: keygen, sign, verify; ensure keys are one-time per sign run.
- Select implementations: fix library + commit/tag; avoid mixed backends in one run.
- Control environment: pin CPU cores, isolate background load, fix governor/turbo policy.
- Build setup: record compiler version, optimization flags, and feature toggles.
- Workload matrix: cover representative message sizes and iterations; include warmups.
- Parameter sets: encode LM-OTS type (e.g., `LMOTS_SHA256_N32_W4`) in `param_set`.
- Measure: wall-clock latency and throughput; optionally memory, cache misses if available.
- Validate: check signature correctness and stability across repeats.

Minimum metadata to record per run:

- CPU model, microcode, RAM, OS/kernel
- Compiler version + flags
- Library name + commit hash/tag
- Algorithm + parameter set (LM-OTS type)
- Message sizes + number of iterations
- Whether turbo scaling was on/off
- RNG source

## Benchmarking harness

`bench/run.sh` collects metadata and writes JSON/CSV results. See `bench/results_schema.json`,
`bench/results_schema.csv`, `bench/example_results.json`, and `bench/example_results.csv`
for the output layout.

## Library

[lms-signature (LM-OTS)](https://docs.rs/lms-signature/latest/lms_signature/ots/index.html)
