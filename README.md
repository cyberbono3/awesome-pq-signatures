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
| 14 | LeanSig | Hash-based | Stateful | Poseidon2-based XMSS-style signature scheme with explicit lifetime parameter. | [leansig](./crates/leansig/README.md) | [leansig](https://github.com/leanEthereum/leanSig) |

## Benchmark Summary

This table mirrors the populated `PQ DSAs.xlsx` sheet. It uses the median `divan` result for the canonical 32-byte benchmark message and groups schemes by statefulness. Stateless schemes are normalized to the workspace security target in [`bench_config.toml`](./bench_config.toml), currently `level3`. Stateful schemes are normalized to the workspace capacity class in [`bench_config.toml`](./bench_config.toml), currently `pow2_10`, and the exact selected capacity is shown explicitly in the `Capacity` column.

Caveat: this normalization is meaningful for schemes that expose comparable NIST-style security categories or parameter sets. For stateful hash-based schemes such as LeanSig, LMS, HSS, XMSS, and XMSS^MT, tree height, layering, and lifetime are primarily capacity or lifetime knobs rather than a single directly comparable security parameter, so those rows should be compared with that limitation in mind.

In practice, this means the current benchmark set is aligned where the workspace can select a like-for-like security target for stateless schemes, and a closest-supported practical capacity class for stateful schemes. It is still not claiming that every stateful scheme row exposes an identical knob or an identical security model.

## Normalization Policy

The repository uses two different comparison strategies, depending on whether a scheme is stateless or stateful.

### Stateless Strategy

The stateless normalization strategy is security-cohort matching.

1. Read `security_target` from [`bench_config.toml`](./bench_config.toml).
2. Select the matching published parameter set for each scheme that exposes comparable security categories.
3. Compare speed and size only after those cohort-matched parameter sets are selected.

Current policy:

- `security_target = "level3"`
- This currently drives variant selection for `ML-DSA`, `CROSS`, `LESS`, `MAYO`, and `SPHINCS+`.
- `Falcon` and `SQISign` remain fixed in this workspace because the currently used dependencies do not expose an exact `level3` selector.

### Stateful Strategy

The stateful normalization strategy is capacity-class matching, not a single security scalar.

1. Read `stateful_capacity_class` from [`bench_config.toml`](./bench_config.toml).
2. Prefer a parameter set whose signing lifetime/tree height is in that capacity class.
3. If a scheme does not expose an exact profile in that class, use the closest supported practical profile and keep the exact capacity visible in the table.
4. Compare stateful rows using all three axes below, not just one label.

Current policy:

- `stateful_capacity_class = "pow2_10"`
- Exact or near-exact class matches: `LMS H10`, `HSS L2`, `XMSS 10`
- Smallest supported larger profiles: `LeanSig 2^18`, `XMSS^MT 2^20`

Stateful comparison axes:

- security strength of the underlying hash/output setting
- total signing capacity per key
- structural tradeoff parameters such as tree height, hierarchy depth, layering, or lifetime

That is why the benchmark tables are grouped by `Statefulness`: stateless schemes are normalized to a common cohort where practical, while stateful schemes are compared within their own capacity class with their exact capacity/lifetime parameters left explicit in the selected parameter set.

| Statefulness | Name | Param Set | Capacity | Family | Keygen (ms) | Sign (ms) | Verify (ms) | PK (B) | SK (B) | Signature (B) |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| Stateless | SQISign | SQISign-lvl1 | - | Isogeny-based | 19.96 | 44.69 | 3.091 | 65 | 353 | 148 |
| Stateless | MAYO-3 | MAYO-3 | - | System-of-equations | 2.402 | 5.663 | 2.092 | 2986 | 32 | 681 |
| Stateless | Falcon-512 | Falcon-512 | - | Lattice-based | 4.886 | 0.1542 | 0.06695 | 897 | 1281 | 659 |
| Stateless | LESS | LESS-400-102 | - | Code-based | 2.657 | 118.2 | 116.7 | 105174 | 48 | 4131 |
| Stateless | ML-DSA-65 (Dilithium) | ML-DSA-65 | - | Lattice-based | 0.333 | 0.6699 | 0.04916 | 1952 | 4032 | 3309 |
| Stateless | SPHINCS+ | SPHINCS+-SHAKE-192f-simple | - | Hash-based | 1.681 | 45.23 | 2.256 | 48 | 96 | 35664 |
| Stateless | CROSS | CROSS-RSDPG-192-BALANCED | - | Code-based | 0.01367 | 1.476 | 0.815 | 83 | 48 | 22464 |
| Stateful | LeanSig | Poseidon-L2^18-TS-w4 | 2^18 | Hash-based | 25090 | 2.888 | 0.3607 | 48 | 86588 | 1632 |
| Stateful | LMS | LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4 | 2^10 | Hash-based | 234.7 | 236 | 0.09906 | 60 | 48 | 2512 |
| Stateful | XMSS | XMSS-SHA2_10_256 | 2^10 | Hash-based | 1645 | 3304 | 0.8081 | 68 | 136 | 2500 |
| Stateful | HSS | HSS-SHA256-H5-W2-L2 | 1023 | Hash-based | 3.876 | 11.65 | 0.1105 | 60 | 48 | 8980 |
| Stateful | XMSS^MT | XMSSMT-SHA2_20/2_256 | 2^20 | Hash-based | 1655 | 4762 | 1.795 | 68 | 135 | 4963 |

## Lowest Signature Size By Statefulness

Sorted by `Statefulness`, then by `Signature (B)` ascending within each group.

| Statefulness | Rank | Name | Param Set | Capacity | Family | Signature (B) | PK (B) | SK (B) | Sign (ms) | Verify (ms) |
|---|---:|---|---|---|---|---:|---:|---:|---:|---:|
| Stateless | 1 | SQISign | SQISign-lvl1 | - | Isogeny-based | 148 | 65 | 353 | 44.69 | 3.091 |
| Stateless | 2 | Falcon-512 | Falcon-512 | - | Lattice-based | 659 | 897 | 1281 | 0.1542 | 0.06695 |
| Stateless | 3 | MAYO-3 | MAYO-3 | - | System-of-equations | 681 | 2986 | 32 | 5.663 | 2.092 |
| Stateless | 4 | ML-DSA-65 (Dilithium) | ML-DSA-65 | - | Lattice-based | 3309 | 1952 | 4032 | 0.6699 | 0.04916 |
| Stateless | 5 | LESS | LESS-400-102 | - | Code-based | 4131 | 105174 | 48 | 118.2 | 116.7 |
| Stateless | 6 | CROSS | CROSS-RSDPG-192-BALANCED | - | Code-based | 22464 | 83 | 48 | 1.476 | 0.815 |
| Stateless | 7 | SPHINCS+ | SPHINCS+-SHAKE-192f-simple | - | Hash-based | 35664 | 48 | 96 | 45.23 | 2.256 |
| Stateful | 1 | LeanSig | Poseidon-L2^18-TS-w4 | 2^18 | Hash-based | 1632 | 48 | 86588 | 2.888 | 0.3607 |
| Stateful | 2 | XMSS | XMSS-SHA2_10_256 | 2^10 | Hash-based | 2500 | 68 | 136 | 3304 | 0.8081 |
| Stateful | 3 | LMS | LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4 | 2^10 | Hash-based | 2512 | 60 | 48 | 236 | 0.09906 |
| Stateful | 4 | XMSS^MT | XMSSMT-SHA2_20/2_256 | 2^20 | Hash-based | 4963 | 68 | 135 | 4762 | 1.795 |
| Stateful | 5 | HSS | HSS-SHA256-H5-W2-L2 | 1023 | Hash-based | 8980 | 60 | 48 | 11.65 | 0.1105 |

## Fastest Sign And Verify By Statefulness

Sorted by `Statefulness`, then by `Sign (ms)` ascending with `Verify (ms)` as the secondary sort within each group.

| Statefulness | Rank | Name | Param Set | Capacity | Family | Sign (ms) | Verify (ms) | Signature (B) | PK (B) | SK (B) |
|---|---:|---|---|---|---|---:|---:|---:|---:|---:|
| Stateless | 1 | Falcon-512 | Falcon-512 | - | Lattice-based | 0.1542 | 0.06695 | 659 | 897 | 1281 |
| Stateless | 2 | ML-DSA-65 (Dilithium) | ML-DSA-65 | - | Lattice-based | 0.6699 | 0.04916 | 3309 | 1952 | 4032 |
| Stateless | 3 | CROSS | CROSS-RSDPG-192-BALANCED | - | Code-based | 1.476 | 0.815 | 22464 | 83 | 48 |
| Stateless | 4 | MAYO-3 | MAYO-3 | - | System-of-equations | 5.663 | 2.092 | 681 | 2986 | 32 |
| Stateless | 5 | SQISign | SQISign-lvl1 | - | Isogeny-based | 44.69 | 3.091 | 148 | 65 | 353 |
| Stateless | 6 | SPHINCS+ | SPHINCS+-SHAKE-192f-simple | - | Hash-based | 45.23 | 2.256 | 35664 | 48 | 96 |
| Stateless | 7 | LESS | LESS-400-102 | - | Code-based | 118.2 | 116.7 | 4131 | 105174 | 48 |
| Stateful | 1 | LeanSig | Poseidon-L2^18-TS-w4 | 2^18 | Hash-based | 2.888 | 0.3607 | 1632 | 48 | 86588 |
| Stateful | 2 | HSS | HSS-SHA256-H5-W2-L2 | 1023 | Hash-based | 11.65 | 0.1105 | 8980 | 60 | 48 |
| Stateful | 3 | LMS | LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4 | 2^10 | Hash-based | 236 | 0.09906 | 2512 | 60 | 48 |
| Stateful | 4 | XMSS | XMSS-SHA2_10_256 | 2^10 | Hash-based | 3304 | 0.8081 | 2500 | 68 | 136 |
| Stateful | 5 | XMSS^MT | XMSSMT-SHA2_20/2_256 | 2^20 | Hash-based | 4762 | 1.795 | 4963 | 68 | 135 |
