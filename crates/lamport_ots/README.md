# Lamport OTS

One-time, hash-based signature scheme implemented in pure Rust with SHA-256.

## Backend

- Algorithm: `Lamport OTS`
- Backend: `custom-rust-sha2`
- Parameter set: `Lamport-OTS-256`
- Library crate entry: `src/lib.rs`

Notes:
- This scheme is one-time: each secret key can sign exactly one message.
- Reusing a secret key is rejected by the API.

## Project layout

- `src/lib.rs`: reusable Lamport OTS implementation (keygen/sign/verify + errors + tests)
- `src/main.rs`: benchmark-style executable summary
- `src/bin/lamport_ots_bench.rs`: direct benchmark command (`OPERATION=keygen|sign|verify`)
- `benches/lamport_ots_divan.rs`: `divan` benchmark suite

## Run (`main.rs`)

```bash
cargo run -p lamport_ots --release --offline --bin lamport_ots
```

Environment overrides:

- `LAMPORT_MESSAGE_SIZE` (default `1024`)
- `LAMPORT_ITERATIONS` (default `100`)
- `LAMPORT_DETERMINISTIC` (default `true`)

## Divan benchmark

Smoke run:

```bash
cargo bench -p lamport_ots --bench lamport_ots_divan --offline -- --test
```

Full run:

```bash
cargo bench -p lamport_ots --bench lamport_ots_divan --offline
```

## Latest local results

Captured at `2026-02-18T21:06:18Z`:

`main.rs` (`cargo run -p lamport_ots --release --offline --bin lamport_ots`)

- `public_key_bytes: 16384`
- `secret_key_bytes: 16384`
- `signature_bytes: 8192`
- `message_size: 1024`
- `iterations: 100`
- `keygen_avg_ns: 177114`
- `sign_avg_ns: 4885`
- `verify_avg_ns: 74334`

`lamport_ots_divan` (`cargo bench -p lamport_ots --bench lamport_ots_divan --offline`)

- `keygen mean: 97.68 µs` (`median: 96.41 µs`)
- `sign(32) mean: 98.62 µs` (`median: 96.99 µs`)
- `sign(1024) mean: 101.8 µs` (`median: 100 µs`)
- `verify(32) mean: 49.23 µs` (`median: 48.35 µs`)
- `verify(1024) mean: 51.97 µs` (`median: 51.2 µs`)

## Benchmark environment (captured)

- Host: `andreis-MacBook-Pro.local`
- OS/kernel: `Darwin 25.1.0 arm64`
- Rust: `rustc 1.87.0-nightly (f4a216d28 2025-03-02)`
- CPU model: `unknown` in sandbox
- RAM: `unknown` in sandbox
