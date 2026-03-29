# SQISign

**SQISign** is an **isogeny-based post-quantum digital signature scheme** built from the arithmetic of supersingular elliptic curves and hard problems around computing structured isogenies between them. Unlike stateful hash-based schemes such as LMS or HSS, SQISign is **stateless**: signatures do not consume one-time leaves or require persistent signing-key state between operations. Its main attraction is the possibility of **very small public keys and signatures** compared with many other post-quantum schemes, while the main tradeoff is a much more specialized mathematical foundation and more implementation complexity than lattice- or hash-based signatures.

## Library

Rust: [sqisign-lvl1](https://crates.io/crates/sqisign-lvl1)

| Crate | Security Level | Public Key | Secret Key | Signature |
| --- | --- | --- | --- | --- |
| `sqisign-lvl1` | NIST Level 1 (AES-128) | 65 bytes | 353 bytes | 148 bytes |

## Implementation Notes

This crate does not implement SQISign from scratch. It wraps the `sqisign-lvl1` Rust crate behind the common workspace signed-message scheme shape used by the benchmark tooling.

Important local choices:
- the wrapper exposes a small `SqisignScheme` API so the crate matches the same benchmark-facing shape as the other signed-message crates
- the benchmark binary uses the shared `pq_bench` signed-message runner and JSON contract
- the Divan benchmark suite uses the shared `pq_bench` signed-message bench scaffolding
- peak heap tracking is provided through the shared `pq_bench` allocation helpers

## `src/main.rs` (`sqisign` binary)

`src/main.rs` is the standard workspace benchmark binary for SQISign. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

The binary is wired through the shared `pq_bench` signed-message runner rather than a crate-local reporting implementation.

Run it with:

```bash
cargo run -p sqisign --bin sqisign -- --format human --message-size 64
```

JSON output:

```bash
cargo run -p sqisign --bin sqisign -- --format json --message-size 64
```

Representative local run:

```text
=== SQISign (SQISign) Benchmark ===

Key generation: 21.98 ms
Signing:        58.18 ms
Verification:   3.0589 ms
Public key:     65 bytes
Secret key:     353 bytes
Signature:      148 bytes
```

## `benches/sqisign_divan.rs` (Divan benchmark suite)

`benches/sqisign_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches, using the shared `pq_bench` Divan benchmark scaffolding.

Run it with:

```bash
cargo bench -p sqisign --bench sqisign_divan
```

Latest observed local median run (captured on 2026-03-17):

```text
SQISign sizes:
  Public key: 65 bytes
  Secret key: 353 bytes
  Signature (message 32 bytes): 148 bytes
  Signature (message 256 bytes): 148 bytes
  Signature (message 1024 bytes): 148 bytes
  Signature (message 4096 bytes): 148 bytes
SQISign peak heap usage:
  Message 32 bytes: sign=328 bytes, verify=212 bytes
  Message 256 bytes: sign=552 bytes, verify=660 bytes
  Message 1024 bytes: sign=1320 bytes, verify=2196 bytes
  Message 4096 bytes: sign=4392 bytes, verify=8340 bytes
Timer precision: 41 ns
sqisign_divan  median
├─ keygen      18.56 ms
├─ sign
│  ├─ 32       41.45 ms
│  ├─ 256      41.7 ms
│  ├─ 1024     41.62 ms
│  ╰─ 4096     41.85 ms
╰─ verify
   ├─ 32       2.896 ms
   ├─ 256      2.911 ms
   ├─ 1024     2.942 ms
   ╰─ 4096     2.916 ms
```
