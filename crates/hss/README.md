# HSS

Hierarchical hash-based signatures benchmark crate.

## Backend

- Algorithm: `HSS`
- Backend: `hbs-lms`
- Parameter sets:
  - `HSS-SHA256-H5-W2-L1`
  - `HSS-SHA256-H5-W2-L2`
- Library crate entry: `src/lib.rs`

Notes:
- HSS signing is stateful: every signature mutates the signing key.
- This crate wraps `hbs-lms` with a small benchmark-oriented API.

## `src/main.rs` (`hss-bench` binary)

`src/main.rs` is a single-run benchmark/report binary. It performs:

- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size and estimated key lifetime reporting

Run it with:

```bash
cargo run -p hss --release --bin hss-bench
```

Environment overrides:

- `PARAM_SET` (default `HSS-SHA256-H5-W2-L1`)
- `MESSAGE_SIZE` (default `1024`)

## `benches/hss_divan.rs` (Divan benchmark suite)

`benches/hss_divan.rs` contains Divan microbenchmarks for:

- `keygen` across parameter sets
- `sign` across message sizes and parameter sets
- `verify` across message sizes and parameter sets

It also prints key/signature sizes, signed-message size, lifetime, and peak heap usage before running Divan.

Run it with:

```bash
cargo bench -p hss --bench hss_divan
```

Smoke run:

```bash
cargo bench -p hss --bench hss_divan -- --test
```

## Library

- Rust: [hbs-lms](https://crates.io/crates/hbs-lms)
- Reference implementation compatibility: [cisco/hash-sigs](https://github.com/cisco/hash-sigs)
