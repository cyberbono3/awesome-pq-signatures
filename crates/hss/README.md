# HSS

**HSS (Hierarchical Signature System)** is a **stateful hash-based post-quantum signature scheme** built by stacking multiple **LMS trees** in a hierarchy. Upper-level LMS keys sign the public keys of lower-level LMS trees, and the **bottom-level LMS tree signs the actual messages**. Like LMS, HSS is stateful: every one-time leaf can be used only once, and the implementation must track and persist signing state safely. Its main benefit is scalability: an HSS key with tree heights **h₀, h₁, …, hₗ₋₁** can sign up to **2^(h₀ + h₁ + … + hₗ₋₁)** messages in total, while avoiding the up-front cost of building one huge single tree. The tradeoff is larger signatures and more operational complexity than plain LMS. ([RFC 8554][rfc8554])

[rfc8554]: https://datatracker.ietf.org/doc/html/rfc8554

Benchmark crate for HSS.

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
- The default benchmark profile follows [`bench_config.toml`](../../bench_config.toml) `stateful_capacity_class`; with the current `pow2_10` setting it selects `HSS-SHA256-H5-W2-L2`.

## `src/main.rs` (`hss` binary)

`src/main.rs` is a single-run benchmark/report binary. It performs:

- key generation timing
- sign timing
- verify timing
- key/signature size and estimated key lifetime reporting

Run it with:

```bash
cargo run -p hss --release --bin hss
```

Environment overrides:

- `PARAM_SET` (default `HSS-SHA256-H5-W2-L2`)
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


## Latest benchmark results

Run timestamp (UTC): `2026-03-26 11:18:00 UTC`

Environment:
- OS: `Darwin 25.1.0 arm64`
- `rustc`: `1.87.0-nightly (f4a216d28 2025-03-02)`
- `cargo`: `1.87.0-nightly (2622e844b 2025-02-28)`

### `hss` (`src/main.rs`)

Command:

```bash
cargo run -p hss --release --bin hss
```

Configuration used:
- `PARAM_SET=HSS-SHA256-H5-W2-L2` (default)
- `MESSAGE_SIZE=1024` (default)

Results:
- Key generation: `3.884084 ms` (`3,884,084 ns`)
- Signing: `11.501041 ms` (`11,501,041 ns`)
- Verification: `114.542 µs` (`114,542 ns`)
- Public key size: `60 bytes`
- Secret key size: `48 bytes`
- Signature size: `8980 bytes`
- Signed message size: `9012 bytes`
- Estimated signatures per key: `1023`

### `hss_divan` (`benches/hss_divan.rs`)

Command:

```bash
cargo bench -p hss --bench hss_divan
```

Reported sizes:
- `HSS-SHA256-H5-W2-L1`: `pk=60`, `sk=48`, `sig(32B)=4464`, `signed(32B)=4496`, `lifetime=31`
- `HSS-SHA256-H5-W2-L2`: `pk=60`, `sk=48`, `sig(32B)=8980`, `signed(32B)=9012`, `lifetime=1023`

Divan timing summary (median, from latest run on `2026-03-26`):
- `keygen`
  - `HSS-SHA256-H5-W2-L1`: `3.775 ms`
  - `HSS-SHA256-H5-W2-L2`: `3.876 ms`
- `sign_l1`
  - `32B`: `3.92 ms`
  - `256B`: `3.932 ms`
  - `1024B`: `3.844 ms`
  - `4096B`: `3.823 ms`
- `sign_l2`
  - `32B`: `11.65 ms`
  - `256B`: `11.55 ms`
  - `1024B`: `11.64 ms`
  - `4096B`: `11.53 ms`
- `verify_l1`
  - `32B`: `59.24 µs`
  - `256B`: `61.54 µs`
  - `1024B`: `57.14 µs`
  - `4096B`: `66.77 µs`
- `verify_l2`
  - `32B`: `110.5 µs`
  - `256B`: `106.6 µs`
  - `1024B`: `109.9 µs`
  - `4096B`: `123 µs`

## Library

- Rust: [hbs-lms](https://crates.io/crates/hbs-lms)
- Reference implementation compatibility: [cisco/hash-sigs](https://github.com/cisco/hash-sigs)
