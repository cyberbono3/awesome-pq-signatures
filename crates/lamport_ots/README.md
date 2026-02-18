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
cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots
```

Environment overrides:

- `LAMPORT_MESSAGE_SIZE` (default `1024`)
- `LAMPORT_ITERATIONS` (default `100`)
- `LAMPORT_DETERMINISTIC` (default `true`)

## Divan benchmark

Smoke run:

```bash
cargo bench --manifest-path crates/lamport_ots/Cargo.toml --bench lamport_ots_divan --offline -- --test
```

Full run:

```bash
cargo bench --manifest-path crates/lamport_ots/Cargo.toml --bench lamport_ots_divan --offline
```

## Direct benchmark commands

```bash
OPERATION=keygen MSG_SIZE=32 ITERATIONS=1000 DETERMINISTIC_RNG=1 cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots_bench
OPERATION=sign MSG_SIZE=32 ITERATIONS=1000 DETERMINISTIC_RNG=1 cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots_bench
OPERATION=verify MSG_SIZE=32 ITERATIONS=1000 DETERMINISTIC_RNG=1 cargo run --manifest-path crates/lamport_ots/Cargo.toml --release --offline --bin lamport_ots_bench
```

## Latest local results

Date: 2026-02-18

`src/main.rs` (`LAMPORT_MESSAGE_SIZE=1024`, `LAMPORT_ITERATIONS=50`):

- `public_key_bytes: 16384`
- `secret_key_bytes: 16384`
- `signature_bytes: 8192`
- `keygen_avg_ns: 124295`
- `sign_avg_ns: 4281`
- `verify_avg_ns: 54690`

`lamport_ots_bench` sample (`MSG_SIZE=32`, `ITERATIONS=1000`):

- `keygen_total_ns: 111773708` (`avg_ns: 111773`)
- `sign_total_ns: 1215208` (`avg_ns: 1215`)
- `verify_total_ns: 59515291` (`avg_ns: 59515`)

## Benchmark environment (captured)

- Host: `andreis-MacBook-Pro.local`
- OS/kernel: `Darwin 25.1.0 arm64`
- Rust: `rustc 1.87.0-nightly (f4a216d28 2025-03-02)`
- CPU model: `unknown` in sandbox
- RAM: `unknown` in sandbox
