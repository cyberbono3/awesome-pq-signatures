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

## `src/main.rs` (`hss` binary)

`src/main.rs` is the standard workspace benchmark binary. It performs:

- key generation timing
- sign timing
- verify timing
- key/signature size and estimated key lifetime reporting

The binary uses the shared `pq_bench` workspace contract and accepts
`--format human|json --message-size N`.

Run it with:

```bash
cargo run -p hss --bin hss -- --format human --message-size 64
```

JSON output:

```bash
cargo run -p hss --bin hss -- --format json --message-size 64
```

Environment overrides:

- `PARAM_SET` (default `HSS-SHA256-H5-W2-L1`)

## `benches/hss_divan.rs` (Divan benchmark suite)

`benches/hss_divan.rs` contains Divan microbenchmarks for:

- `keygen` across parameter sets
- `sign` across message sizes and parameter sets
- `verify` across message sizes and parameter sets

It also prints key/signature sizes, signed-message size, lifetime, and peak heap usage before running Divan, using shared `pq_bench` bench helpers where possible.

Run it with:

```bash
cargo bench -p hss --bench hss_divan
```


## Representative benchmark results

### `hss` (`src/main.rs`)

Command:

```bash
cargo run -p hss --bin hss -- --format human --message-size 64
```

Configuration used:
- `PARAM_SET=HSS-SHA256-H5-W2-L1` (default)

Representative local results:
- Key generation: `7.881083 ms` (`7,881,083 ns`)
- Signing: `7.372208 ms` (`7,372,208 ns`)
- Verification: `108.375 µs` (`108,375 ns`)
- Public key size: `60 bytes`
- Secret key size: `48 bytes`
- Signature size: `4464 bytes`
- Signed message size: `5488 bytes`
- Estimated signatures per key: `31`

### `hss_divan` (`benches/hss_divan.rs`)

Command:

```bash
cargo bench -p hss --bench hss_divan
```

Reported sizes:
- `HSS-SHA256-H5-W2-L1`: `pk=60`, `sk=48`, `sig(32B)=4464`, `signed(32B)=4496`, `lifetime=31`
- `HSS-SHA256-H5-W2-L2`: `pk=60`, `sk=48`, `sig(32B)=8980`, `signed(32B)=9012`, `lifetime=1023`

Representative local Divan timing summary (median):
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
