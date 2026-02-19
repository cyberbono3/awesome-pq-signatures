# LM-OTS

Leighton-Micali one-time signature benchmarking crate.

## Library

- Crate: [`lms-signature`](https://crates.io/crates/lms-signature)
- Version: `0.1.0-rc.2`
- LM-OTS module: [`lms_signature::ots`](https://docs.rs/lms-signature/0.1.0-rc.2/lms_signature/ots/index.html)

## Backend

- Algorithm: `LM-OTS`
- Backend: `lms-signature-0.1.0-rc.2`
- Default parameter set: `LMOTS_SHA256_N32_W4`

## Project layout

- `src/lib.rs`: reusable LM-OTS benchmark adapter over `lms-signature`
- `src/main.rs`: single-run benchmark/report binary
- `src/bin/lm_ots_bench.rs`: operation runner (`OPERATION=keygen|sign|verify`) for scripted harness
- `benches/lm_ots_divan.rs`: Divan benchmark suite
- `bench/run.sh`: matrix runner producing JSON/CSV benchmark reports

## `src/main.rs` (`lm_ots` binary)

Single-run benchmark output includes:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run -p lm_ots --release --offline --bin lm_ots
```

Environment overrides:

- `LMOTS_PARAM_SET` (default `LMOTS_SHA256_N32_W4`)
- `LMOTS_MESSAGE_SIZE` (default `1024`)
- `LMOTS_DETERMINISTIC` (default `true`)

## `benches/lm_ots_divan.rs` (Divan benchmark suite)

Divan microbenchmarks:
- `keygen`
- `sign` across `32, 256, 1024, 4096` byte messages
- `verify` across `32, 256, 1024, 4096` byte messages

The benchmark asserts the implementation identity before running:

- `algorithm = LM-OTS`
- `backend = lms-signature-0.1.0-rc.2`
- `param_set = LMOTS_SHA256_N32_W4`

Run it with:

```bash
cargo bench -p lm_ots --bench lm_ots_divan --offline
```

Latest local run (captured on `2026-02-19T15:49:16Z`):

- Sizes:
- `public_key_bytes: 56`
- `secret_key_bytes: 2165`
- `signature_bytes: 2180`
- Peak heap usage:
- `sign(32|256|1024|4096): 52 bytes`
- `verify(32|256|1024|4096): 0 bytes`
- Divan timing summary (`median`, `mean`):
- `keygen: 45.41 µs, 45.84 µs`
- `sign(32): 68.64 µs, 70.73 µs`
- `sign(256): 66.95 µs, 67.19 µs`
- `sign(1024): 68.08 µs, 68.52 µs`
- `sign(4096): 69.24 µs, 71.09 µs`
- `verify(32): 23.22 µs, 23.48 µs`
- `verify(256): 22.77 µs, 23.56 µs`
- `verify(1024): 25.83 µs, 26.75 µs`
- `verify(4096): 27.08 µs, 27.33 µs`
