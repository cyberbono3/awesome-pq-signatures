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

## Latest benchmark results

Run timestamp (UTC): `2026-02-19 11:02:56 UTC`

Environment:
- OS: `Darwin 25.1.0 arm64`
- `rustc`: `1.87.0-nightly (f4a216d28 2025-03-02)`
- `cargo`: `1.87.0-nightly (2622e844b 2025-02-28)`

### `hss-bench` (`src/main.rs`)

Command:

```bash
cargo run -p hss --release --bin hss-bench
```

Configuration used:
- `PARAM_SET=HSS-SHA256-H5-W2-L1` (default)
- `MESSAGE_SIZE=1024` (default)

Results:
- Key generation: `7.881083 ms` (`7,881,083 ns`)
- Signing: `7.372208 ms` (`7,372,208 ns`)
- Verification: `108.375 µs` (`108,375 ns`)
- Public key size: `60 bytes`
- Secret key size: `48 bytes`
- Signature size: `4464 bytes`
- Signed message size: `5488 bytes`
- Estimated signatures per key: `31`
- Peak heap usage:
  - Signing: `0 bytes`
  - Verification: `0 bytes`

### `hss_divan` (`benches/hss_divan.rs`)

Command:

```bash
cargo bench -p hss --bench hss_divan
```

Reported sizes:
- `HSS-SHA256-H5-W2-L1`: `pk=60`, `sk=48`, `sig(32B)=4464`, `signed(32B)=4496`, `lifetime=31`
- `HSS-SHA256-H5-W2-L2`: `pk=60`, `sk=48`, `sig(32B)=8980`, `signed(32B)=9012`, `lifetime=1023`
- Peak heap usage (sign/verify): `0 bytes` for message sizes `32`, `256`, `1024`, `4096`

Divan timing summary (median, from latest run):
- `keygen`
  - `HSS-SHA256-H5-W2-L1`: `3.822 ms`
  - `HSS-SHA256-H5-W2-L2`: `3.820 ms`
- `sign_l1`
  - `32B`: `3.824 ms`
  - `256B`: `3.782 ms`
  - `1024B`: `3.832 ms`
  - `4096B`: `3.842 ms`
- `sign_l2`
  - `32B`: `11.43 ms`
  - `256B`: `11.43 ms`
  - `1024B`: `11.43 ms`
  - `4096B`: `11.44 ms`
- `verify_l1`
  - `32B`: `54.08 µs`
  - `256B`: `54.87 µs`
  - `1024B`: `56.45 µs`
  - `4096B`: `67.10 µs`
- `verify_l2`
  - `32B`: `107.4 µs`
  - `256B`: `114.1 µs`
  - `1024B`: `112.4 µs`
  - `4096B`: `119.5 µs`

## Library

- Rust: [hbs-lms](https://crates.io/crates/hbs-lms)
- Reference implementation compatibility: [cisco/hash-sigs](https://github.com/cisco/hash-sigs)
