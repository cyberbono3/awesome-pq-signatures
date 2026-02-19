# FORS

## Overview

This crate implements the Forest of Random Subsets (FORS) component used by SLH-DSA (Stateless Hash-based Digital Signature Algorithm), following the finalized NIST standard in [FIPS-205](https://csrc.nist.gov/pubs/fips/205/final). It is intended as a focused building block for SLH-DSA implementations rather than a standalone signature scheme.

## Signature Characteristics

- One-time, hash-based, stateless component inside SLH-DSA.
- Security relies on preimage resistance of the underlying hash functions.
- Signatures consist of selected secret values and authentication paths over small Merkle trees.
- Large signature sizes compared to lattice-based schemes; verification is hash-heavy.
- Not a standalone scheme; it is combined with other SLH-DSA components.

## Pros

- Conservative security assumptions (hash functions only).
- Stateless design avoids state management pitfalls of classic hash-based signatures.
- Simple construction and straightforward verification logic.

## Cons

- Large signatures and public keys compared to many alternatives.
- Slower signing and verification due to heavy hashing.
- Primarily useful as a building block rather than a general-purpose standalone scheme.



[slh-dsa](https://crates.io/crates/slh-dsa)
