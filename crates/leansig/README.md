# LeanSig

Poseidon2-based XMSS signature scheme with Target Sum encoding, from the [leanSig](https://github.com/leanEthereum/leanSig) project.

## Library

[leansig](https://github.com/leanEthereum/leanSig) (git dependency, rev `16c660e`)

## `src/main.rs` (`leansig` binary)

`src/main.rs` is the standard workspace benchmark binary for LeanSig (Poseidon – Lifetime 2^18 – Target Sum – w 4). It performs:
- key generation timing
- secret-key preparation (advance to epoch 1)
- sign timing
- verify timing
- key/signature size reporting (SSZ serialized)

The binary uses the shared `pq_bench` workspace contract and accepts
`--format human|json --message-size N`. In the aggregated runner it is executed
as a subprocess and returns JSON back to `bench_runner`.

Run it with:

```bash
cargo run --bin leansig -- --format human --message-size 32
```

JSON output:

```bash
cargo run --bin leansig -- --format json --message-size 64
```

Note: benchmark timings vary by machine, compiler version, and system load.
