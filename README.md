# Comparing & Benchmarking Post Quantum Digital Security Schemes

Benchmarking post-quantum signature schemes (Falcon-512, Dilithium, SPHINCS+ and more) with real performance numbers, sizes, security assumptions, implementation risks, and zkVM verification overhead to guide production-ready choices.

## Workspace schemes

Each workspace crate has a short description and a pointer to a Rust library or reference implementation.
LM-OTS is typically used inside LMS as its one-time signature component, so LMS is listed as the primary scheme here.

| No. | Signature scheme | Category | Statefulness | Description | Workspace | Library |
|---:|---|---|---|---|---|---|
| 1 | Falcon | Lattice-based | Non-stateful | Lattice-based signature scheme with small signatures. | [falcon](./falcon/README.md) | [pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon) |
| 2 | Dilithium (ML-DSA) | Lattice-based | Non-stateful | Lattice-based signature scheme standardized as ML-DSA. | [dilithium](./dilithium/README.md) | [ml-dsa](https://crates.io/crates/ml-dsa)<br>[pqcrypto-mldsa](https://crates.io/crates/pqcrypto-mldsa) |
| 3 | Lamport one-time signature (OTS) | Hash-based | Stateful | One-time hash-based signature using many random secrets. | [lamport_ots](./lamport_ots/README.md) | [lamport_signature](https://crates.io/crates/lamport_signature)<br>[lamport_sigs](https://crates.io/crates/lamport_sigs)<br>[lsig](https://crates.io/crates/lsig) |
| 4 | Winternitz OTS (W-OTS) | Hash-based | Stateful | One-time hash-based signature with Winternitz chaining. | [winternitz_ots](./winternitz_ots/README.md) | [winternitz-ots](https://crates.io/crates/winternitz-ots)<br>[wots-rs](https://crates.io/crates/wots-rs) |
| 5 | LMS | Hash-based | Stateful | Stateful Merkle tree signature scheme (RFC 8554). | [lms](./lms/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 6 | HSS | Hash-based | Stateful | Hierarchical LMS for large key hierarchies. | [hss](./hss/README.md) | [hbs-lms](https://crates.io/crates/hbs-lms) |
| 7 | XMSS | Hash-based | Stateful | Hash-based Merkle signature scheme (RFC 8391). | [xmss](./xmss/README.md) | [xmss (RustCrypto)](https://github.com/RustCrypto/signatures/tree/master/xmss) |
| 8 | XMSSMT | Hash-based | Stateful | Multi-tree XMSS variant for faster signing. | [xmssmt](./xmssmt/README.md) | [xmss (RustCrypto)](https://github.com/RustCrypto/signatures/tree/master/xmss) |
| 9 | SPHINCS+ (SLH-DSA) | Hash-based | Non-stateful | Stateless hash-based signature scheme. | [sphincs_plus](./sphincs_plus/README.md) | [pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus) |
| 10 | SQIsign | Isogeny-based | Non-stateful | Isogeny-based signature scheme from supersingular isogenies. | - | [sqisign](https://crates.io/crates/sqisign)<br>[sqisign-rs](https://crates.io/crates/sqisign-rs)<br>[sqisign.org](https://sqisign.org) |
| 11 | Mayo | System-of-equations | Non-stateful | Multivariate post-quantum signature scheme (MAYO). | - | [pq-mayo](https://crates.io/crates/pq-mayo) |
| 12 | CROSS | Code-based | Non-stateful | Code-based post-quantum signature candidate (CROSS). | [cross](./crates/cross/README.md) | [cross-crypto.com](https://www.cross-crypto.com/cross.html)<br>[C](https://github.com/CROSS-signature/CROSS-implementation) |
| 13 | LESS | Code-based | Non-stateful | Code-based post-quantum signature candidate (LESS). | - | [less-project.com](https://www.less-project.com/)<br>[C](https://github.com/less-sig/LESS) |
| 14 | SQIsignHD | Isogeny-based | Non-stateful | Isogeny-based SQIsign high-dimensional variant (research line). | - | No library |
| 15 | Wave/Wavelet | Code-based | Non-stateful | Code-based post-quantum signature family (Wave/Wavelet). | - | No library |
