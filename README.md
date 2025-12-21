# Comparing & Benchmarking Post Quantum Digital Security Schemes

Benchmarking post-quantum signature schemes (Falcon-512, Dilithium, SPHINCS+ and more) with real performance numbers, sizes, security assumptions, implementation risks, and zkVM verification overhead to guide production-ready choices.

# Post-quantum secure signature schemes 

| Signature scheme | Rust implementation? | Rust example implementation(s) | Notes |
|---|---:|---|---|
| Lamport one-time signature (OTS) | ✅ Yes | [lamport_signature](https://crates.io/crates/lamport_signature)<br>[lamport_sigs](https://crates.io/crates/lamport_sigs)<br>[lsig](https://crates.io/crates/lsig) | One-time (stateful) hash-based signatures. |
| Winternitz one-time signature (W-OTS) | ✅ Yes | [winternitz-ots](https://crates.io/crates/winternitz-ots)<br>[wots-rs](https://crates.io/crates/wots-rs) | One-time (stateful) hash-based signatures. |
| Leighton–Micali one-time signature (LM-OTS) | ✅ Yes | [lms-signature (LM-OTS module)](https://docs.rs/lms-signature/latest/lms_signature/ots/index.html)<br>[trailofbits/lms-rust](https://github.com/trailofbits/lms-rust) | LM-OTS is a modified Winternitz-style OTS used by LMS. |
| Leighton–Micali signature scheme (LMS) | ✅ Yes | [lms-signature](https://docs.rs/lms-signature/latest/lms_signature/)<br>[hbs-lms](https://crates.io/crates/hbs-lms)<br>[trailofbits/lms-rust](https://github.com/trailofbits/lms-rust) | Stateful Merkle-tree signature scheme (RFC 8554 family). |
| Hierarchical Signature System (HSS) | ⚠️ Not found (public Rust impl) | — | Hypertree variant of LMS; I didn’t find a maintained Rust implementation that exposes HSS APIs (LMS/LM-OTS exist). |
| eXtended Merkle Signature Scheme (XMSS) | ✅ Yes | [xmss-rust](https://gitlab.zapb.de/crypto/xmss-rust) | Rust implementation exists (RFC 8391). |
| XMSS multi-tree variant (XMSS^MT / XMSSMT) | ✅ Yes | [thomwiggers/xmss-rs](https://github.com/thomwiggers/xmss-rs) | Repo describes an XMSS-MT instantiation (used in experiments). |
| SPHINCS+ (officially SLH-DSA) | ✅ Yes | [slh-dsa](https://crates.io/crates/slh-dsa)<br>[Argyle-Software/sphincsplus](https://github.com/Argyle-Software/sphincsplus)<br>[pqcrypto-sphincsplus](https://crates.io/crates/pqcrypto-sphincsplus) | Stateless hash-based signature scheme. |
| SPHINCS (original, predecessor to SPHINCS+) | 🟨 Partial (variant in Rust) | [gendx/gravity-rs](https://github.com/gendx/gravity-rs) | I didn’t find a direct Rust implementation of original SPHINCS-256; Gravity-SPHINCS is a related variant with a Rust implementation. |
| HORS (Hash to Obtain Random Subset) | ⚠️ Not found (public Rust impl) | — | Few-times signature (FTS) scheme used as a concept/building block. |
| HORST | ⚠️ Not found (public Rust impl) | — | Few-times signature scheme (“with Trees”). |
| FORS (Forest Of Random Subsets) | ✅ Yes (inside SPHINCS+/SLH-DSA code) | [slh-dsa](https://crates.io/crates/slh-dsa) | Used inside SPHINCS+/SLH-DSA; typically not exposed as a standalone scheme. |
| Dilithium (officially ML-DSA) | ✅ Yes | [ml-dsa](https://crates.io/crates/ml-dsa)<br>[pqcrypto-mldsa](https://crates.io/crates/pqcrypto-mldsa) | Lattice-based signature scheme (FIPS 204). |
