# Comparing & Benchmarking Post Quantum Digital Security Schemes

Benchmarking post-quantum signature schemes (Falcon-512, Dilithium, SPHINCS+ and more) with real performance numbers, sizes, security assumptions, implementation risks to guide production-ready choices.

## Workspace schemes

Each workspace crate has a short description and the single library or reference implementation actually used by that benchmark crate.
LM-OTS is typically used inside LMS as its one-time signature component, so LMS is listed as the primary scheme here.

| No. | Signature scheme | Category | Statefulness | Description | Workspace | Library |
|---:|---|---|---|---|---|---|
| 1 | Falcon | Lattice-based | Stateless | Lattice-based signature scheme with small signatures. | [falcon](./crates/falcon/README.md) | [pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon) |
| 2 | Dilithium (ML-DSA) | Lattice-based | Stateless | Lattice-based signature scheme standardized as ML-DSA. | [dilithium](./crates/dilithium/README.md) | [ml-dsa](https://crates.io/crates/ml-dsa) |
| 3 | Winternitz OTS (W-OTS) | Hash-based | Stateful | One-time hash-based signature with Winternitz chaining. | [winternitz_ots](./crates/winternitz_ots/README.md) | [winternitz-ots](https://crates.io/crates/winternitz-ots) |
| 4 | LMS | Hash-based | Stateful | Stateful Merkle tree signature scheme (RFC 8554). | [lms](./crates/lms/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 5 | HSS | Hash-based | Stateful | Hierarchical LMS for large key hierarchies. | [hss](./crates/hss/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 6 | XMSS | Hash-based | Stateful | Hash-based Merkle signature scheme (RFC 8391). | [xmss](./crates/xmss/README.md) | [xmss](https://crates.io/crates/xmss) |
| 7 | XMSSMT | Hash-based | Stateful | Multi-tree XMSS variant for faster signing. | [xmssmt](./crates/xmssmt/README.md) | [xmss](https://crates.io/crates/xmss) |
| 8 | SPHINCS+ (SLH-DSA) | Hash-based | Stateless | Stateless hash-based signature scheme. | [sphincs_plus](./crates/sphincs_plus/README.md) | [pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus) |
| 9 | SQIsign | Isogeny-based | Stateless | Isogeny-based signature scheme from supersingular isogenies. | [sqisign](./crates/sqisign/README.md) | [sqisign-lvl1](https://crates.io/crates/sqisign-lvl1) |
| 10 | Mayo | System-of-equations | Stateless | Multivariate post-quantum signature scheme (MAYO). | [mayo](./crates/mayo/README.md) | [pq-mayo](https://crates.io/crates/pq-mayo) |
| 11 | CROSS | Code-based | Stateless | Code-based post-quantum signature candidate (CROSS). | [cross](./crates/cross/README.md) | [CROSS C reference implementation](https://github.com/CROSS-signature/CROSS-implementation) |
| 12 | LESS | Code-based | Stateless | Code-based post-quantum signature candidate (LESS). | [less](./crates/less/README.md) | [LESS C implementation](https://github.com/less-sig/LESS) |

## Benchmark interfaces

The workspace now uses one shared benchmark-binary contract across the standalone benchmark executables:

- `--format human|json`
- `--message-size N`

The `human` format keeps each crate's readable benchmark summary. The `json` format emits a single `BenchmarkBinaryReport` payload that is consumed by the workspace runner and is stable enough for scripting.

Representative examples:

```bash
cargo run -p dilithium --bin dilithium -- --format json
cargo run -p hss --bin hss -- --format human --message-size 256
cargo run -p leansig-bench --bin leansig -- --format json
```

Notes:

- `LMS` and `HSS` still honor `PARAM_SET` for selecting a non-default parameter set.
- Some crates are materially slower than others. `XMSS`, `XMSS^MT`, and `LeanSig` can take much longer to complete a single benchmark run.

## Crate architecture

This is the implementation architecture of each workspace crate, not the cryptographic category.

| Crate | Architecture |
|---|---|
| `pq_bench` | Shared support crate. Owns the canonical benchmark message/seed config, shared size/report value objects, JSON and human report types, binary CLI parsing, allocation tracking, timing helpers, stateful benchmark-report helpers, FFI signed-message helpers, and the narrow workspace macros used by other crates. |
| `bench_runner` | Workspace orchestrator. Structured as CLI parsing, registry/spec selection, pure and subprocess adapters, app orchestration, and CSV/display reporting. Runs some schemes in-process and others as JSON-speaking subprocesses. |
| `dilithium` | Pure Rust wrapper over `ml-dsa`, with deterministic seeded key generation, allocator tracking, and the shared benchmark binary/Divan surfaces. |
| `falcon` | Pure Rust wrapper over `pqcrypto-falcon`’s signed-message API, exposed through the shared `pq_bench` signed-message scheme surface and shared benchmark/reporting glue. |
| `winternitz_ots` | Pure Rust wrapper around `winternitz-ots`, with Blake2b message-digest preprocessing, local size helpers, allocator tracking, and the shared benchmark/reporting contract. |
| `lms` | Pure Rust benchmark wrapper over `hbs-lms`, with explicit parameter-set enums, stateful key wrappers, derived size logic, and benchmark-facing APIs for stateful signing. |
| `hss` | Pure Rust benchmark wrapper over `hbs-lms` hierarchical mode, with parameter-set enums, stateful key wrappers, hierarchy-aware reporting, and benchmark-facing APIs for stateful signing. |
| `mayo` | Pure Rust wrapper over `pq-mayo`, with deterministic seeded key generation, context validation, allocator tracking, and the shared benchmark/reporting contract. |
| `xmss` | Pure Rust wrapper over RustCrypto `xmss`, using parameter-set dispatch, opaque key wrappers, shared stateful benchmark-report helpers, and the shared benchmark binary/Divan structure. |
| `xmssmt` | Pure Rust wrapper over RustCrypto `xmss` multi-tree types, using parameter-set dispatch, opaque key-pair wrappers, shared stateful benchmark-report helpers, and the shared benchmark binary/Divan structure. |
| `sphincs_plus` | Pure Rust wrapper over `pqcrypto-sphincsplus`’s signed-message API, with allocator tracking and the shared benchmark/reporting contract. |
| `cross` | FFI crate over a vendored upstream C reference implementation. Uses shared `pq_bench` FFI signed-message macros/helpers, deterministic RNG seeding, allocator tracking, and a mutex around shared native RNG state. |
| `less` | FFI crate over a vendored upstream C implementation. Uses the same shared `pq_bench` FFI signed-message architecture as `cross`: deterministic RNG seeding, allocator tracking, and serialized access around native shared state. |
| `sqisign` | Thin Rust wrapper over `sqisign-lvl1`, generated through the shared simple signed-message scheme macro, with shared benchmark binary and Divan scaffolding. |
| `leansig-bench` | Benchmark wrapper around the upstream `leansig` git dependency. Adds fixed-size benchmark message conversion, epoch-preparation logic for the secret key, and the shared benchmark/reporting contract. |

## Crate commands

The commands below use the exact package and binary names from this workspace.
For Divan targets, `cargo bench ...` runs the full suite and `cargo bench ... -- --list`
is a fast smoke check if you only want to validate target wiring.

### Scheme crates

- `dilithium`
  Binary: `cargo run -p dilithium --bin dilithium -- --format json`
  Divan: `cargo bench -p dilithium --bench dilithium_divan`
- `falcon`
  Binary: `cargo run -p falcon --bin falcon-bench -- --format json`
  Divan: `cargo bench -p falcon --bench falcon_divan`
- `winternitz_ots`
  Binary: `cargo run -p winternitz_ots --bin winternitz_ots -- --format json`
  Divan: `cargo bench -p winternitz_ots --bench winternitz_ots_divan`
- `lms`
  Binary: `cargo run -p lms --bin lms -- --format json`
  Divan: `cargo bench -p lms --bench lms_divan`
  Alternate parameter set: `PARAM_SET=<name> cargo run -p lms --bin lms -- --format human`
- `hss`
  Binary: `cargo run -p hss --bin hss -- --format json`
  Divan: `cargo bench -p hss --bench hss_divan`
  Alternate parameter set: `PARAM_SET=<name> cargo run -p hss --bin hss -- --format human`
- `mayo`
  Binary: `cargo run -p mayo --bin mayo -- --format json`
  Divan: `cargo bench -p mayo --bench mayo_divan`
- `xmss`
  Binary: `cargo run -p xmss-bench --bin xmss -- --format json`
  Divan: `cargo bench -p xmss-bench --bench xmss_divan`
- `xmssmt`
  Binary: `cargo run -p xmssmt-bench --bin xmssmt -- --format json`
  Divan: `cargo bench -p xmssmt-bench --bench xmssmt_divan`
- `sphincs_plus`
  Binary: `cargo run -p sphincs_plus --bin sphincs-plus-bench -- --format json`
  Divan: `cargo bench -p sphincs_plus --bench sphincs_plus_divan`
- `cross`
  Binary: `cargo run -p cross --bin cross -- --format json`
  Divan: `cargo bench -p cross --bench cross_divan`
- `less`
  Binary: `cargo run -p less --bin less -- --format json`
  Divan: `cargo bench -p less --bench less_divan`
- `sqisign`
  Binary: `cargo run -p sqisign --bin sqisign -- --format json`
  Divan: `cargo bench -p sqisign --bench sqisign_divan`
- `leansig`
  Binary: `cargo run -p leansig-bench --bin leansig -- --format json`
  Divan: `cargo bench -p leansig-bench --bench leansig_divan`

### Support crates

- `pq_bench`
  Tests: `cargo test -p pq_bench`
  Binary contract fixture: `cargo test -p pq_bench --test binary_contract`
- `bench_runner`
  Aggregate run: `cargo run -p bench_runner --bin bench_runner -- --runs 1 --message-size 64 --output benchmarks/results.csv`
  Filtered run: `cargo run -p bench_runner --bin bench_runner -- --runs 1 --only dilithium --message-size 64 --output /tmp/bench_runner_dilithium.csv`

## Shared crate patterns

`pq_bench` is now the shared support layer for benchmark-facing crate structure. New crates should prefer these patterns instead of open-coding benchmark glue:

- Use normal functions first. The exported macros are intentionally narrow and are only for repeated structural boilerplate.
- Use the shared binary contract for standalone benchmark executables: parse `--format human|json --message-size N`, build a `BenchmarkBinaryReport`, and emit either human or JSON output through `pq_bench`.
- Use the shared size/report value objects from `pq_bench` when a crate only needs benchmark-facing size or report data. Avoid cloning those structs locally.
- Use the shared stateful benchmark helpers for LMS, HSS, XMSS, and XMSS^MT style flows where key generation returns mutable signing state and report assembly follows the standard timed keygen/sign/verify pattern.
- Use `declare_simple_signed_message_scheme!` for wrappers around native Rust keygen/sign/verify implementations that already expose normal Rust types.
- Use `declare_ffi_signed_message_backend!` plus `declare_ffi_signed_message_scheme!` for FFI-backed signed-message crates that need deterministic RNG setup, byte-dimension discovery, and the standard scheme wrapper API.
- Use `run_standard_signed_message_scheme_main!` for standalone signed-message benchmark binaries once a crate exposes the common scheme API.
- Use `declare_signed_message_divan_bench!` for the standard Divan bench shape when a crate follows the common signed-message scheme API.
- Use `build_support/native_cc.rs` for native `cc::Build` setup when a crate vendors C code and only differs by source lists, defines, flags, and output name.

Stateful benchmark boundary:

- `pq_bench` owns the generic timing/report assembly for stateful schemes.
- Crates such as `lms`, `hss`, `xmss`, and `xmssmt` keep parameter validation, key wrapper types, and cryptographic operations local.
- `main.rs` files should stay as thin adapters from crate-specific metadata into the shared binary/report contract.

## Workspace runner

Use the aggregated runner to benchmark multiple schemes and write a CSV summary:

```bash
cargo run -p bench_runner --bin bench_runner -- --runs 3 --message-size 64 --output benchmarks/results.csv
```

Useful filters:

- `--only TEXT`: repeatable substring filter against algorithm names
- `--param-set TEXT`: repeatable substring filter against parameter-set names
- `--skip-ffi`: skip only the FFI-backed subprocess crates
- `--skip-subprocess`: skip all subprocess crates, including LeanSig
- `--message-size N`: override the shared benchmark message size

Example:

```bash
cargo run -p bench_runner --bin bench_runner -- --runs 1 --only leansig --message-size 64 --output /tmp/leansig.csv
```

Common recipes:

```bash
# Benchmark one pure-Rust crate
cargo run -p bench_runner --bin bench_runner -- --runs 1 --only dilithium --message-size 64 --output /tmp/dilithium.csv

# Benchmark one subprocess crate
cargo run -p bench_runner --bin bench_runner -- --runs 1 --only cross --message-size 64 --output /tmp/cross.csv

# Benchmark only in-process crates
cargo run -p bench_runner --bin bench_runner -- --runs 1 --skip-subprocess --message-size 64 --output /tmp/pure_rust.csv

# Benchmark everything except FFI-backed subprocess crates
cargo run -p bench_runner --bin bench_runner -- --runs 1 --skip-ffi --message-size 64 --output /tmp/no_ffi.csv

# Narrow by both algorithm and parameter set
cargo run -p bench_runner --bin bench_runner -- --runs 1 --only xmss --param-set sha2 --message-size 64 --output /tmp/xmss_sha2.csv
```

Runner execution model:

- Pure Rust schemes such as Dilithium, Falcon, Mayo, Winternitz OTS, LMS, HSS, XMSS, and XMSS^MT run in-process.
- Standalone binaries such as CROSS, LESS, SQISign, and LeanSig run as subprocesses and return JSON back to `bench_runner`.

Filter behavior:

- `--skip-ffi` skips only the FFI-backed subprocess schemes.
- `--skip-subprocess` skips all subprocess-run schemes, including LeanSig.
