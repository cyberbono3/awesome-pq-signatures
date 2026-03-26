# LeanSig

Poseidon2-based XMSS signature scheme with Target Sum encoding, from the [leanSig](https://github.com/leanEthereum/leanSig) project.

## Library

[leansig](https://github.com/leanEthereum/leanSig) (git dependency, rev `16c660e`)

The default benchmark profile follows [`bench_config.toml`](../../bench_config.toml) `stateful_capacity_class`; with the current `pow2_10` setting it selects the smallest supported larger profile, `Poseidon-L2^18-TS-w4`.

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

## `benches/leansig_divan.rs` (Divan benchmark suite)

`benches/leansig_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign`
- `verify`

It also prints serialized public-key, secret-key, and signature sizes before executing the Divan benches.

Run it with:

```bash
cargo bench -p leansig-bench --bench leansig_divan -- --sample-count 10 --max-time 1
```

Latest observed local median run (captured on 2026-03-24 09:47:49 UTC, bounded run with `--sample-count 10 --max-time 1`):

```text
LeanSig sizes:
  Public key: 48 bytes
  Secret key: 86588 bytes
  Signature:  1632 bytes

Divan timing summary (median):
  keygen: 25.09 s
  sign: 2.888 ms
  verify: 360.7 µs
```

Note: benchmark timings vary by machine, compiler version, and system load.
