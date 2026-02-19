# LMS

Leighton-Micali signatures benchmark crate.

## Backend

- Algorithm: `LMS`
- Backend: `lms-signature`
- Parameter sets:
  - `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`
  - `LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4`
- Library crate entry: `src/lib.rs`

Notes:
- LMS signing is stateful: every signature advances key index `q`.
- This crate wraps `lms-signature` with a benchmark-oriented API.

## `src/main.rs` (`lms-bench` binary)

`src/main.rs` is a single-run benchmark/report binary. It performs:

- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size and remaining-signature reporting

Run it with:

```bash
cargo run -p lms --release --bin lms-bench
```

Environment overrides:

- `PARAM_SET` (default `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`)
- `MESSAGE_SIZE` (default `1024`)

## `benches/lms_divan.rs` (Divan benchmark suite)

`benches/lms_divan.rs` contains Divan microbenchmarks for:

- `keygen` across parameter sets
- `sign` across message sizes and parameter sets
- `verify` across message sizes and parameter sets

It also prints key/signature sizes, signed-message size, key lifetime estimate,
and peak heap usage before running Divan.

Run it with:

```bash
cargo bench -p lms --bench lms_divan
```

Smoke run:

```bash
cargo bench -p lms --bench lms_divan -- --test
```

## Latest benchmark results

Run timestamp (UTC): `2026-02-19 11:41:52 UTC`

Environment:
- OS: `Darwin 25.1.0 arm64`
- `rustc`: `1.87.0-nightly (f4a216d28 2025-03-02)`
- `cargo`: `1.87.0-nightly (2622e844b 2025-02-28)`

### `lms-bench` (`src/main.rs`)

Command:

```bash
cargo run -p lms --release --bin lms-bench
```

Configuration used:
- `PARAM_SET=LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4` (default)
- `MESSAGE_SIZE=1024` (default)

Results:
- Key generation: `1.555417 ms` (`1,555,417 ns`)
- Signing: `37.25 µs` (`37,250 ns`)
- Verification: `30.125 µs` (`30,125 ns`)
- Public key size: `56 bytes`
- Secret key size: `60 bytes`
- Signature size: `2348 bytes`
- Signed message size: `3372 bytes`
- Estimated signatures remaining: `31`
- Peak heap usage:
  - Signing: `0 bytes`
  - Verification: `0 bytes`

### `lms_divan` (`benches/lms_divan.rs`)

Command:

```bash
cargo bench -p lms --bench lms_divan
```

Reported sizes:
- `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`: `pk=56`, `sk=60`, `sig(32B)=2348`, `signed(32B)=2380`, `lifetime=32`
- `LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4`: `pk=56`, `sk=60`, `sig(32B)=2508`, `signed(32B)=2540`, `lifetime=1024`
- Peak heap usage (sign/verify): `0 bytes` for message sizes `32`, `256`, `1024`, `4096`

Divan timing summary (median, from latest run):
- `keygen`
  - `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`: `1.526 ms`
  - `LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4`: `48.54 ms`
- `sign_h5w4`
  - `32B`: `28.85 µs`
  - `256B`: `29.52 µs`
  - `1024B`: `29.49 µs`
  - `4096B`: `30.64 µs`
- `sign_h10w4`
  - `32B`: `31.43 µs`
  - `256B`: `32.04 µs`
  - `1024B`: `32.02 µs`
  - `4096B`: `33.49 µs`
- `verify_h5w4`
  - `32B`: `24.70 µs`
  - `256B`: `24.29 µs`
  - `1024B`: `23.83 µs`
  - `4096B`: `26.66 µs`
- `verify_h10w4`
  - `32B`: `24.37 µs`
  - `256B`: `23.79 µs`
  - `1024B`: `25.49 µs`
  - `4096B`: `28.27 µs`

## Library

- Rust: [lms-signature](https://docs.rs/lms-signature/latest/lms_signature/)
