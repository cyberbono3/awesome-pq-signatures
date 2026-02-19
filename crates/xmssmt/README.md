# XMSSMT

XMSSMT benchmark workspace wired to the upstream
[`thomwiggers/xmss-rs`](https://github.com/thomwiggers/xmss-rs) implementation.

## Backend

- Algorithm: `XMSSMT`
- Backend: `thomwiggers/xmss-rs` (C reference backend via FFI)
- Parameter sets:
  - `XMSSMT-L1` (`xmss_rs::level1`)
  - `XMSSMT-L3` (`xmss_rs::level3`)
  - `XMSSMT-L5` (`xmss_rs::level5`)
- Library crate entry: `src/lib.rs`

Notes:
- Signing is stateful: secret keys are mutated by `sign`.
- The first build fetches `xmss-rs` from GitHub and compiles its C backend.
- `libcrypto` must be available on the system linker path.

## Project layout

- `src/lib.rs`: reusable scheme model + timing/allocation helpers
- `src/main.rs`: one-shot benchmark report binary (`xmssmt-bench`)
- `benches/xmssmt_divan.rs`: Divan microbench suite

## Run (`src/main.rs`)

```bash
cargo run -p xmssmt --release --bin xmssmt-bench
```

Environment overrides:

- `PARAM_SET` (default `XMSSMT-L1`)
- `MESSAGE_SIZE` (default `1024`)

## Divan benchmark

Smoke run:

```bash
cargo bench -p xmssmt --bench xmssmt_divan -- --test
```

Full run:

```bash
cargo bench -p xmssmt --bench xmssmt_divan
```

## Strategy (same pattern as Dilithium/Falcon)

- Use `src/main.rs` for a human-readable single-run benchmark report.
- Use Divan for stable microbench trends on `keygen`, `sign`, and `verify`.
- Record param set, message size, and environment metadata with each benchmark capture.

## Upstream reference

[xmss-rs](https://github.com/thomwiggers/xmss-rs)
