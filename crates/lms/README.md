# LMS

**LMS (Leighton–Micali Signature)** is a **stateful hash-based post-quantum signature scheme** built from **LM-OTS one-time signatures** arranged under a **single Merkle tree**. Each signature consumes exactly one unused leaf, so **state must be updated after every signature** and **a used leaf must never be reused**. An LMS key with tree height **h** can sign **at most 2^h messages** total; after that, the key is exhausted and must be replaced. LMS is simple and conservative, but careful state management is mandatory because key/leaf reuse breaks the scheme's security. ([RFC 8554][rfc8554])

[rfc8554]: https://datatracker.ietf.org/doc/html/rfc8554

Benchmark crate for LMS.

## Backend

- Algorithm: `LMS`
- Backend: `hbs-lms`
- Parameter sets:
  - `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`
  - `LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4`
- Library crate entry: `src/lib.rs`

Notes:
- LMS signing is stateful: every signature advances the secret-key state.
- This crate wraps `hbs-lms` with a benchmark-oriented API.

## `src/main.rs` (`lms` binary)

`src/main.rs` is a single-run benchmark/report binary. It performs:

- key generation timing
- sign timing
- verify timing
- key/signature size and remaining-signature reporting

Run it with:

```bash
cargo run -p lms --release --bin lms
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

Observed size output from the latest `lms_divan` run:
- `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`: `pk=56`, `sk=48`, `sig(32B)=2352`, `signed(32B)=2384`, `lifetime=32`
- `LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4`: `pk=56`, `sk=48`, `sig(32B)=2512`, `signed(32B)=2544`, `lifetime=1024`

Median timings from `cargo bench -p lms --bench lms_divan` on `2026-03-17`:
- `keygen`
  - `LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4`: `6.683 ms`
  - `LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4`: `211.1 ms`
- `sign_h5w4`
  - `32B`: `6.646 ms`
  - `256B`: `6.624 ms`
  - `1024B`: `6.647 ms`
  - `4096B`: `6.664 ms`
- `sign_h10w4`
  - `32B`: `212.7 ms`
  - `256B`: `213.6 ms`
  - `1024B`: `213 ms`
  - `4096B`: `212 ms`
- `verify_h5w4`
  - `32B`: `102.6 µs`
  - `256B`: `103 µs`
  - `1024B`: `102.2 µs`
  - `4096B`: `118.9 µs`
- `verify_h10w4`
  - `32B`: `120.4 µs`
  - `256B`: `96.45 µs`
  - `1024B`: `117.7 µs`
  - `4096B`: `115.4 µs`

## Library

- Rust: [hbs-lms](https://docs.rs/hbs-lms/latest/hbs_lms/)
