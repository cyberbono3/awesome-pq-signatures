# Comparing & Benchmarking Post Quantum Digital Security Schemes

Benchmarking post-quantum signature schemes (Falcon-512, Dilithium, SPHINCS+ and more) with real performance numbers, sizes, security assumptions, implementation risks, and zkVM verification overhead to guide production-ready choices.

## Workspace schemes

Each workspace crate has a short description and the single library or reference implementation actually used by that benchmark crate.
LM-OTS is typically used inside LMS as its one-time signature component, so LMS is listed as the primary scheme here.

| No. | Signature scheme | Category | Statefulness | Description | Workspace | Library |
|---:|---|---|---|---|---|---|
| 1 | Falcon | Lattice-based | Stateless | Lattice-based signature scheme with small signatures. | [falcon](./crates/falcon/README.md) | [pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon) |
| 2 | Dilithium (ML-DSA) | Lattice-based | Stateless | Lattice-based signature scheme standardized as ML-DSA. | [dilithium](./crates/dilithium/README.md) | [ml-dsa](https://crates.io/crates/ml-dsa) |
| 3 | Lamport one-time signature (OTS) | Hash-based | Stateful | One-time hash-based signature using many random secrets. | [lamport_ots](./crates/lamport_ots/README.md) | Internal Rust implementation |
| 4 | Winternitz OTS (W-OTS) | Hash-based | Stateful | One-time hash-based signature with Winternitz chaining. | [winternitz_ots](./crates/winternitz_ots/README.md) | [winternitz-ots](https://crates.io/crates/winternitz-ots) |
| 5 | LMS | Hash-based | Stateful | Stateful Merkle tree signature scheme (RFC 8554). | [lms](./crates/lms/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 6 | HSS | Hash-based | Stateful | Hierarchical LMS for large key hierarchies. | [hss](./crates/hss/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 7 | XMSS | Hash-based | Stateful | Hash-based Merkle signature scheme (RFC 8391). | [xmss](./crates/xmss/README.md) | [xmss](https://crates.io/crates/xmss) |
| 8 | XMSSMT | Hash-based | Stateful | Multi-tree XMSS variant for faster signing. | [xmssmt](./crates/xmssmt/README.md) | [xmss](https://crates.io/crates/xmss) |
| 9 | SPHINCS+ (SLH-DSA) | Hash-based | Stateless | Stateless hash-based signature scheme. | [sphincs_plus](./crates/sphincs_plus/README.md) | [pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus) |
| 10 | SQIsign | Isogeny-based | Stateless | Isogeny-based signature scheme from supersingular isogenies. | [sqisign](./crates/sqisign/README.md) | [sqisign-lvl1](https://crates.io/crates/sqisign-lvl1) |
| 11 | Mayo | System-of-equations | Stateless | Multivariate post-quantum signature scheme (MAYO). | [mayo](./crates/mayo/README.md) | [pq-mayo](https://crates.io/crates/pq-mayo) |
| 12 | CROSS | Code-based | Stateless | Code-based post-quantum signature candidate (CROSS). | [cross](./crates/cross/README.md) | [CROSS C reference implementation](https://github.com/CROSS-signature/CROSS-implementation) |
| 13 | LESS | Code-based | Stateless | Code-based post-quantum signature candidate (LESS). | [less](./crates/less/README.md) | [LESS C implementation](https://github.com/less-sig/LESS) |

## Benchmark interfaces

The workspace now uses one shared benchmark-binary contract across the standalone benchmark executables:

- `--format human|json`
- `--message-size N`

The `human` format keeps each crate's readable benchmark summary. The `json` format emits a single `BenchmarkBinaryReport` payload that is consumed by the workspace runner and is stable enough for scripting.

Representative examples:

```bash
cargo run -p dilithium -- --format json --message-size 64
cargo run -p hss -- --format human --message-size 256
cargo run -p lamport_ots --bin lamport_ots -- --format json --message-size 64
cargo run --bin leansig -- --format json --message-size 64
```

Notes:

- `LMS` and `HSS` still honor `PARAM_SET` for selecting a non-default parameter set.
- Some crates are materially slower than others. `XMSS`, `XMSS^MT`, and `LeanSig` can take much longer to complete a single benchmark run.

## Shared crate patterns

`pq_bench` is now the shared support layer for benchmark-facing crate structure. New crates should prefer these patterns instead of open-coding benchmark glue:

- Use normal functions first. The exported macros are intentionally narrow and are only for repeated structural boilerplate.
- Use the shared binary contract for standalone benchmark executables: parse `--format human|json --message-size N`, build a `BenchmarkBinaryReport`, and emit either human or JSON output through `pq_bench`.
- Use `declare_simple_signed_message_scheme!` for wrappers around native Rust keygen/sign/verify implementations that already expose normal Rust types.
- Use `declare_ffi_signed_message_backend!` plus `declare_ffi_signed_message_scheme!` for FFI-backed signed-message crates that need deterministic RNG setup, byte-dimension discovery, and the standard scheme wrapper API.
- Use `run_standard_signed_message_scheme_main!` for standalone signed-message benchmark binaries once a crate exposes the common scheme API.
- Use `declare_signed_message_divan_bench!` for the standard Divan bench shape when a crate follows the common signed-message scheme API.
- Use `build_support/native_cc.rs` for native `cc::Build` setup when a crate vendors C code and only differs by source lists, defines, flags, and output name.

## Workspace runner

Use the aggregated runner to benchmark multiple schemes and write a CSV summary:

```bash
cargo run --bin bench_runner -- --runs 3 --message-size 64 --output benchmarks/results.csv
```

Useful filters:

- `--only TEXT`
- `--param-set TEXT`
- `--skip-ffi`
- `--skip-subprocess`

Example:

```bash
cargo run --bin bench_runner -- --runs 1 --only leansig --message-size 64 --output /tmp/leansig.csv
```

Runner execution model:

- Pure Rust schemes such as Dilithium, Falcon, Mayo, Lamport OTS, LMS, HSS, XMSS, and XMSS^MT run in-process.
- Standalone binaries such as CROSS, LESS, SQISign, and LeanSig run as subprocesses and return JSON back to `bench_runner`.

Filter behavior:

- `--skip-ffi` skips only the FFI-backed subprocess schemes.
- `--skip-subprocess` skips all subprocess-run schemes, including LeanSig.
