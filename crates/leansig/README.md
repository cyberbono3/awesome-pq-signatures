# LeanSig

Poseidon2-based XMSS signature scheme with Target Sum encoding, from the [leanSig](https://github.com/leanEthereum/leanSig) project.

## Library

[leansig](https://github.com/leanEthereum/leanSig) (git dependency, rev `16c660e`)

## `src/main.rs` (`leansig` binary)

`src/main.rs` is a single-run benchmark/report binary for LeanSig (Poseidon – Lifetime 2^18 – Target Sum – w 4). It performs:
- key generation timing
- secret-key preparation (advance to epoch 1)
- sign timing
- verify timing
- key/signature size reporting (SSZ serialized)

Run it with:

```bash
cargo run --release --bin leansig
```

Note: benchmark timings vary by machine, compiler version, and system load.
