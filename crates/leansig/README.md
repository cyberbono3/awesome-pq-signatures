# LeanSig

Hash-based synchronized signatures using tweakable hash functions and incomparable encodings, designed for post-quantum Ethereum.

## Library

[leanSig](https://github.com/leanEthereum/leanSig) (GitHub)

## Overview

LeanSig implements XMSS-like hash-based signatures from incomparable encodings, using Poseidon2 as the underlying hash function. It is a **synchronized** (stateful) signature scheme where keys are associated with a fixed lifetime divided into discrete epochs. Each key pair signs at most once per epoch.

This crate wraps the upstream `leansig` library and provides a single-run benchmark binary.

## `src/main.rs` (`leansig-bench` binary)

`src/main.rs` runs a single keygen → sign → verify cycle for one LeanSig instantiation and reports:
- key generation timing
- sign timing
- verify timing
- key / signature sizes (SSZ serialized)

The default instantiation is **Poseidon, Lifetime 2^18, Target Sum encoding, w = 4**.

Run it with:

```bash
cargo run --release -p leansig-bench --bin leansig-bench
```

> **Note:** Key generation for LeanSig is expensive (builds Merkle trees over 2^18 leaves). Running in `--release` mode is strongly recommended. Expect keygen to take several seconds even on fast hardware.

## Benchmark Environment

Note: benchmark timings vary by machine, compiler version, and system load.
