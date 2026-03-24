# Comparing & Benchmarking Post Quantum Digital Security Schemes

Benchmarking post-quantum signature schemes (Falcon-512, Dilithium, SPHINCS+ and more) with real performance numbers, sizes, security assumptions, implementation risks, and zkVM verification overhead to guide production-ready choices.

## Workspace schemes

Each workspace crate has a short description and the single library or reference implementation actually used by that benchmark crate.
LM-OTS is typically used inside LMS as its one-time signature component, so LMS is listed as the primary scheme here.

| No. | Signature scheme | Category | Statefulness | Description | Workspace | Library |
|---:|---|---|---|---|---|---|
| 1 | Falcon | Lattice-based | Non-stateful | Lattice-based signature scheme with small signatures. | [falcon](./crates/falcon/README.md) | [pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon) |
| 2 | Dilithium (ML-DSA) | Lattice-based | Non-stateful | Lattice-based signature scheme standardized as ML-DSA. | [dilithium](./crates/dilithium/README.md) | [ml-dsa](https://crates.io/crates/ml-dsa) |
| 3 | Lamport one-time signature (OTS) | Hash-based | Stateful | One-time hash-based signature using many random secrets. | [lamport_ots](./crates/lamport_ots/README.md) | Internal Rust implementation |
| 4 | Winternitz OTS (W-OTS) | Hash-based | Stateful | One-time hash-based signature with Winternitz chaining. | [winternitz_ots](./crates/winternitz_ots/README.md) | [winternitz-ots](https://crates.io/crates/winternitz-ots) |
| 5 | LMS | Hash-based | Stateful | Stateful Merkle tree signature scheme (RFC 8554). | [lms](./crates/lms/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 6 | HSS | Hash-based | Stateful | Hierarchical LMS for large key hierarchies. | [hss](./crates/hss/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 7 | XMSS | Hash-based | Stateful | Hash-based Merkle signature scheme (RFC 8391). | [xmss](./crates/xmss/README.md) | [xmss](https://crates.io/crates/xmss) |
| 8 | XMSSMT | Hash-based | Stateful | Multi-tree XMSS variant for faster signing. | [xmssmt](./crates/xmssmt/README.md) | [xmss](https://crates.io/crates/xmss) |
| 9 | SPHINCS+ (SLH-DSA) | Hash-based | Non-stateful | Stateless hash-based signature scheme. | [sphincs_plus](./crates/sphincs_plus/README.md) | [pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus) |
| 10 | SQIsign | Isogeny-based | Non-stateful | Isogeny-based signature scheme from supersingular isogenies. | [sqisign](./crates/sqisign/README.md) | [sqisign-lvl1](https://crates.io/crates/sqisign-lvl1) |
| 11 | Mayo | System-of-equations | Non-stateful | Multivariate post-quantum signature scheme (MAYO). | [mayo](./crates/mayo/README.md) | [pq-mayo](https://crates.io/crates/pq-mayo) |
| 12 | CROSS | Code-based | Non-stateful | Code-based post-quantum signature candidate (CROSS). | [cross](./crates/cross/README.md) | [CROSS C reference implementation](https://github.com/CROSS-signature/CROSS-implementation) |
| 13 | LESS | Code-based | Non-stateful | Code-based post-quantum signature candidate (LESS). | [less](./crates/less/README.md) | [LESS C implementation](https://github.com/less-sig/LESS) |

## Benchmark Summary

This table mirrors the populated `PQ DSAs.xlsx` sheet. It uses the default parameter set for each scheme and the median `divan` result for the canonical 32-byte benchmark message.

| Name | Param Set | Family | Keygen | Sign | Verify | PK | SK | Signature |
|---|---|---|---:|---:|---:|---:|---:|---:|
| SQISign | SQISign-lvl1 | Isogeny-based | 18.56 ms | 41.45 ms | 2.896 ms | 65 | 353 | 148 |
| MAYO-1 | MAYO-1 | System-of-equations | 844.4 µs | 2.04 ms | 763.8 µs | 1420 | 24 | 454 |
| Falcon-512 | Falcon-512 | Lattice-based | 5.264 ms | 151 us | 21.61 us | 897 | 1281 | 653 |
| LESS | LESS-252-45 | Code-based | 2.072 ms | 19.06 ms | 18.69 ms | 97484 | 32 | 1329 |
| LeanSig | Poseidon-L2^18-TS-w4 | Hash-based | 25.09 s | 2.888 ms | 360.7 µs | 48 | 86588 | 1632 |
| LMS | LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4 | Hash-based | 6.683 ms | 6.646 ms | 102.6 µs | 56 | 48 | 2352 |
| XMSS | XMSS-SHA2_10_256 | Hash-based | 1.645 s | 3.304 s | 808.1 us | 68 | 136 | 2500 |
| ML-DSA-65 (Dilithium) | ML-DSA-65 | Lattice-based | 201.3 us | 569.5 us | 44.58 us | 1952 | 4032 | 3309 |
| HSS | HSS-SHA256-H5-W2-L1 | Hash-based | 3.822 ms | 3.824 ms | 54.08 µs | 60 | 48 | 4464 |
| XMSS^MT | XMSSMT-SHA2_20/2_256 | Hash-based | 1.655 s | 4.762 s | 1.795 ms | 68 | 135 | 4963 |
| SPHINCS+ | SPHINCS+-SHAKE-128f-simple | Hash-based | 1.498 ms | 24.98 ms | 1.507 ms | 32 | 64 | 17088 |
| CROSS | CROSS-RSDPG-192-BALANCED | Code-based | 12.44 us | 1.371 ms | 786.8 us | 83 | 48 | 22464 |
