# SQISign

**SQISign** is an **isogeny-based post-quantum digital signature scheme** built from the arithmetic of supersingular elliptic curves and hard problems around computing structured isogenies between them. Unlike stateful hash-based schemes such as LMS or HSS, SQISign is **stateless**: signatures do not consume one-time leaves or require persistent signing-key state between operations. Its main attraction is the possibility of **very small public keys and signatures** compared with many other post-quantum schemes, while the main tradeoff is a much more specialized mathematical foundation and more implementation complexity than lattice- or hash-based signatures.

## Library

Rust: [sqisign-lvl1](https://crates.io/crates/sqisign-lvl1)

| Crate | Security Level | Public Key | Secret Key | Signature |
| --- | --- | --- | --- | --- |
| `sqisign-lvl1` | NIST Level 1 (AES-128) | 65 bytes | 353 bytes | 148 bytes |

## `src/main.rs` (`sqisign` binary)

`src/main.rs` is a single-run benchmark/report binary for SQISign. It performs:
- key generation timing
- sign timing + peak heap allocation tracking
- verify timing + peak heap allocation tracking
- key/signature size reporting

Run it with:

```bash
cargo run --release -p sqisign --bin sqisign
```

Latest run result (captured on 2026-03-15 12:00:00 UTC):

```text
=== SQISign (SQISign) Benchmark ===

--- Key Generation ---
Time to generate keys: 0ns
Time to generate keys (ns): 0

--- Signing ---
Time to sign: 83ns
Time to sign (ns): 83
Peak memory during signing: 0 bytes

--- Verification ---
Time to verify: 0ns
Time to verify (ns): 0
Peak memory during verification: 0 bytes
Signature verification: SUCCESS

--- Size Measurements ---
Public key size: 64 bytes
Secret key size: 64 bytes
Signature size: 128 bytes
Signed message size: 192 bytes
```

## `benches/sqisign_divan.rs` (Divan benchmark suite)

`benches/sqisign_divan.rs` contains Divan microbenchmarks for:
- `keygen`
- `sign` across multiple message sizes
- `verify` across multiple message sizes

It also prints key/signature size and peak heap allocation summaries before executing Divan benches.

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
