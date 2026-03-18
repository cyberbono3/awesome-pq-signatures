use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const HASH_SIZE: usize = 32;
pub const BITS: usize = HASH_SIZE * 8;
pub const SECRET_ELEMENTS: usize = BITS * 2;
pub const SIGNATURE_ELEMENTS: usize = BITS;

#[derive(Clone, Debug)]
pub struct LamportPublicKey {
    elements: Vec<[u8; HASH_SIZE]>,
}

impl LamportPublicKey {
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.elements.len() * HASH_SIZE
    }
}

#[derive(Clone, Debug)]
pub struct LamportSecretKey {
    elements: Vec<[u8; HASH_SIZE]>,
    used: bool,
}

impl LamportSecretKey {
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.elements.len() * HASH_SIZE
    }

    pub fn used(&self) -> bool {
        self.used
    }
}

#[derive(Clone, Debug)]
pub struct LamportSignature {
    elements: Vec<[u8; HASH_SIZE]>,
}

impl LamportSignature {
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.elements.len() * HASH_SIZE
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LamportSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LamportOtsScheme;

pub const LAMPORT_OTS_SCHEME: LamportOtsScheme = LamportOtsScheme;

impl LamportOtsScheme {
    pub const fn algorithm_name(&self) -> &'static str {
        "Lamport OTS"
    }

    pub const fn backend_name(&self) -> &'static str {
        "custom-rust-sha2"
    }

    pub const fn param_set_name(&self) -> &'static str {
        "Lamport-OTS-256"
    }

    pub const fn max_signatures_per_key(&self) -> usize {
        1
    }

    pub const fn sizes(&self) -> LamportSizes {
        LamportSizes {
            public_key_bytes: SECRET_ELEMENTS * HASH_SIZE,
            secret_key_bytes: SECRET_ELEMENTS * HASH_SIZE,
            signature_bytes: SIGNATURE_ELEMENTS * HASH_SIZE,
        }
    }

    pub fn keypair(&self) -> (LamportPublicKey, LamportSecretKey) {
        let mut rng = XorShift64::new(default_seed());
        self.keypair_with_rng(&mut rng)
    }

    pub fn keypair_with_seed(
        &self,
        seed: u64,
    ) -> (LamportPublicKey, LamportSecretKey) {
        let mut rng = XorShift64::new(seed);
        self.keypair_with_rng(&mut rng)
    }

    pub fn keypair_with_rng(
        &self,
        rng: &mut XorShift64,
    ) -> (LamportPublicKey, LamportSecretKey) {
        let mut secret_elements = Vec::with_capacity(SECRET_ELEMENTS);
        let mut public_elements = Vec::with_capacity(SECRET_ELEMENTS);

        for _ in 0..SECRET_ELEMENTS {
            let mut secret = [0_u8; HASH_SIZE];
            rng.fill_bytes(&mut secret);
            public_elements.push(hash_bytes(&secret));
            secret_elements.push(secret);
        }

        (
            LamportPublicKey {
                elements: public_elements,
            },
            LamportSecretKey {
                elements: secret_elements,
                used: false,
            },
        )
    }

    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &mut LamportSecretKey,
    ) -> Result<LamportSignature, LamportError> {
        if secret_key.used {
            return Err(LamportError::KeyAlreadyUsed);
        }
        if secret_key.elements.len() != SECRET_ELEMENTS {
            return Err(LamportError::InvalidSecretKeyLength {
                expected: SECRET_ELEMENTS,
                actual: secret_key.elements.len(),
            });
        }

        let digest = hash_bytes(message);
        let signature = sign_digest(&digest, &secret_key.elements);
        secret_key.used = true;

        Ok(LamportSignature {
            elements: signature,
        })
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &LamportSignature,
        public_key: &LamportPublicKey,
    ) -> Result<bool, LamportError> {
        if signature.elements.len() != SIGNATURE_ELEMENTS {
            return Err(LamportError::InvalidSignatureLength {
                expected: SIGNATURE_ELEMENTS,
                actual: signature.elements.len(),
            });
        }
        if public_key.elements.len() != SECRET_ELEMENTS {
            return Err(LamportError::InvalidPublicKeyLength {
                expected: SECRET_ELEMENTS,
                actual: public_key.elements.len(),
            });
        }

        let digest = hash_bytes(message);
        for i in 0..SIGNATURE_ELEMENTS {
            let idx = selected_secret_index(&digest, i);
            if hash_bytes(&signature.elements[i]) != public_key.elements[idx] {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut offset = 0;
        while offset < out.len() {
            let chunk = self.next_u64().to_le_bytes();
            let take = (out.len() - offset).min(chunk.len());
            out[offset..offset + take].copy_from_slice(&chunk[..take]);
            offset += take;
        }
    }
}

#[derive(Debug)]
pub enum LamportError {
    KeyAlreadyUsed,
    InvalidSecretKeyLength { expected: usize, actual: usize },
    InvalidPublicKeyLength { expected: usize, actual: usize },
    InvalidSignatureLength { expected: usize, actual: usize },
}

impl fmt::Display for LamportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyAlreadyUsed => {
                write!(f, "Lamport secret key already used")
            }
            Self::InvalidSecretKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid secret key length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid public key length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    f,
                    "invalid signature length: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl Error for LamportError {}

pub fn seed_from_str(seed: &str) -> u64 {
    let digest = hash_bytes(seed.as_bytes());
    let mut seed_bytes = [0_u8; 8];
    seed_bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(seed_bytes)
}

fn default_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id() as u64;
    (now.as_nanos() as u64) ^ (pid << 32)
}

fn hash_bytes(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0_u8; HASH_SIZE];
    out.copy_from_slice(&digest[..HASH_SIZE]);
    out
}

fn sign_digest(
    digest: &[u8; HASH_SIZE],
    secret_elements: &[[u8; HASH_SIZE]],
) -> Vec<[u8; HASH_SIZE]> {
    let mut signature = Vec::with_capacity(SIGNATURE_ELEMENTS);
    for i in 0..SIGNATURE_ELEMENTS {
        let idx = selected_secret_index(digest, i);
        signature.push(secret_elements[idx]);
    }
    signature
}

fn selected_secret_index(digest: &[u8; HASH_SIZE], bit_index: usize) -> usize {
    let byte = digest[bit_index / 8];
    let bit = (byte >> (7 - (bit_index % 8))) & 1;
    (bit_index * 2) + bit as usize
}

#[cfg(test)]
mod tests {
    use super::{LamportOtsScheme, XorShift64};

    #[test]
    fn sign_and_verify_roundtrip() {
        let scheme = LamportOtsScheme;
        let mut rng = XorShift64::new(42);
        let message = b"lamport-roundtrip-test";

        let (public_key, mut secret_key) = scheme.keypair_with_rng(&mut rng);
        let signature = scheme
            .sign(message, &mut secret_key)
            .expect("sign should succeed");

        let is_valid = scheme
            .verify(message, &signature, &public_key)
            .expect("verify should succeed");
        assert!(is_valid, "signature must verify");
    }

    #[test]
    fn key_reuse_is_rejected() {
        let scheme = LamportOtsScheme;
        let mut rng = XorShift64::new(42);

        let (_public_key, mut secret_key) = scheme.keypair_with_rng(&mut rng);
        let _first = scheme
            .sign(b"first", &mut secret_key)
            .expect("first sign should succeed");

        let second = scheme.sign(b"second", &mut secret_key);
        assert!(
            second.is_err(),
            "second sign must fail because key is one-time"
        );
    }

    #[test]
    fn verify_rejects_other_message() {
        let scheme = LamportOtsScheme;
        let mut rng = XorShift64::new(42);

        let (public_key, mut secret_key) = scheme.keypair_with_rng(&mut rng);
        let signature = scheme
            .sign(b"message-a", &mut secret_key)
            .expect("sign should succeed");

        let is_valid = scheme
            .verify(b"message-b", &signature, &public_key)
            .expect("verify should succeed");
        assert!(!is_valid, "different message must not verify");
    }
}
