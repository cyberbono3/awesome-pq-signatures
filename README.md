# Comparing & Benchmarking Post Quantum Digital Security Schemes

Benchmarking post-quantum signature schemes (Falcon-512, Dilithium, SPHINCS+ and more) with real performance numbers, sizes, security assumptions, implementation risks, and zkVM verification overhead to guide production-ready choices.

## Workspace schemes

Each workspace crate has a short description and a pointer to a Rust library or reference implementation.

| No. | Signature scheme | Description | Workspace | Library |
|---:|---|---|---|---|
| 1 | Falcon | Lattice-based signature scheme with small signatures. | [falcon](./falcon/README.md) | [pqcrypto-falcon](https://crates.io/crates/pqcrypto-falcon) |
| 2 | Dilithium (ML-DSA) | Lattice-based signature scheme standardized as ML-DSA. | [dilithium](./dilithium/README.md) | [ml-dsa](https://crates.io/crates/ml-dsa)<br>[pqcrypto-mldsa](https://crates.io/crates/pqcrypto-mldsa) |
| 3 | Lamport one-time signature (OTS) | One-time hash-based signature using many random secrets. | [lamport_ots](./lamport_ots/README.md) | [lamport_signature](https://crates.io/crates/lamport_signature)<br>[lamport_sigs](https://crates.io/crates/lamport_sigs)<br>[lsig](https://crates.io/crates/lsig) |
| 4 | Winternitz OTS (W-OTS) | One-time hash-based signature with Winternitz chaining. | [winternitz_ots](./winternitz_ots/README.md) | [winternitz-ots](https://crates.io/crates/winternitz-ots)<br>[wots-rs](https://crates.io/crates/wots-rs) |
| 5 | LM-OTS | Leighton-Micali one-time signature used by LMS. | [lm_ots](./lm_ots/README.md) | [lms-signature (LM-OTS)](https://docs.rs/lms-signature/latest/lms_signature/ots/index.html)<br>[trailofbits/lms-rust](https://github.com/trailofbits/lms-rust) |
| 6 | LMS | Stateful Merkle tree signature scheme (RFC 8554). | [lms](./lms/README.md) | [lms-signature](https://docs.rs/lms-signature/latest/lms_signature/)<br>[hbs-lms](https://crates.io/crates/hbs-lms)<br>[trailofbits/lms-rust](https://github.com/trailofbits/lms-rust) |
| 7 | HSS | Hierarchical LMS for large key hierarchies. | [hss](./hss/README.md) | C: [cisco/hash-sigs](https://github.com/cisco/hash-sigs) |
| 8 | XMSS | Hash-based Merkle signature scheme (RFC 8391). | [xmss](./xmss/README.md) | [xmss-rust](https://gitlab.zapb.de/crypto/xmss-rust) |
| 9 | XMSSMT | Multi-tree XMSS variant for faster signing. | [xmssmt](./xmssmt/README.md) | [xmss-rs](https://github.com/thomwiggers/xmss-rs) |
| 10 | SPHINCS+ (SLH-DSA) | Stateless hash-based signature scheme. | [sphincs_plus](./sphincs_plus/README.md) | [slh-dsa](https://crates.io/crates/slh-dsa)<br>[Argyle-Software/sphincsplus](https://github.com/Argyle-Software/sphincsplus)<br>[pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus) |
| 11 | SPHINCS (original) | Predecessor to SPHINCS+ with older parameters. | [sphincs](./sphincs/README.md) | [gravity-rs](https://github.com/gendx/gravity-rs) |
| 12 | HORS | Few-time hash-based signature scheme. | [hors](./hors/README.md) | Java: [Orfey95/HORS](https://github.com/Orfey95/HORS) |
| 13 | HORST | Few-time hash-based signature with trees. | [horst](./horst/README.md) | C: [gravity-postquantum/prune-horst](https://github.com/gravity-postquantum/prune-horst) |
| 14 | FORS | Forest of Random Subsets used inside SPHINCS+. | [fors](./fors/README.md) | [slh-dsa](https://crates.io/crates/slh-dsa) |
