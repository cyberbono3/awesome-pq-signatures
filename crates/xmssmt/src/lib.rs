use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use rustcrypto_xmss::{
    KeyPair, XmssMtSha2_20_2_256, XmssMtSha2_20_4_256, XmssMtSha2_40_2_256,
    XmssParameter,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmssmtParamSet {
    Sha2_20_2_256,
    Sha2_20_4_256,
    Sha2_40_2_256,
}

impl XmssmtParamSet {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha2_20_2_256 => "XMSSMT-SHA2_20/2_256",
            Self::Sha2_20_4_256 => "XMSSMT-SHA2_20/4_256",
            Self::Sha2_40_2_256 => "XMSSMT-SHA2_40/2_256",
        }
    }

    pub const fn oid(self) -> u32 {
        match self {
            Self::Sha2_20_2_256 => 0x0001_0001,
            Self::Sha2_20_4_256 => 0x0001_0002,
            Self::Sha2_40_2_256 => 0x0001_0003,
        }
    }

    pub const fn total_tree_height(self) -> u32 {
        match self {
            Self::Sha2_20_2_256 => 20,
            Self::Sha2_20_4_256 => 20,
            Self::Sha2_40_2_256 => 40,
        }
    }

    pub const fn depth(self) -> u32 {
        match self {
            Self::Sha2_20_2_256 => 2,
            Self::Sha2_20_4_256 => 4,
            Self::Sha2_40_2_256 => 2,
        }
    }

    pub const fn all() -> &'static [Self] {
        &[
            Self::Sha2_20_2_256,
            Self::Sha2_20_4_256,
            Self::Sha2_40_2_256,
        ]
    }
}

impl FromStr for XmssmtParamSet {
    type Err = XmssmtError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "XMSSMT-SHA2_20/2_256" => Ok(Self::Sha2_20_2_256),
            "XMSSMT-SHA2_20/4_256" => Ok(Self::Sha2_20_4_256),
            "XMSSMT-SHA2_40/2_256" => Ok(Self::Sha2_40_2_256),
            _ => Err(XmssmtError::UnsupportedParamSet(value.to_owned())),
        }
    }
}

/// Opaque wrapper around an XMSS^MT key pair.
///
/// We keep the `KeyPair` object alive rather than serializing/deserializing
/// because the upstream `xmss` crate has an OID collision between XMSS and
/// XMSS^MT raw OIDs that prevents correct round-tripping through bytes.
pub struct XmssmtKeyPair {
    inner: XmssmtKeyPairInner,
    param_set: XmssmtParamSet,
}

enum XmssmtKeyPairInner {
    Sha2_20_2(KeyPair<XmssMtSha2_20_2_256>),
    Sha2_20_4(KeyPair<XmssMtSha2_20_4_256>),
    Sha2_40_2(KeyPair<XmssMtSha2_40_2_256>),
}

impl XmssmtKeyPair {
    pub fn param_set(&self) -> XmssmtParamSet {
        self.param_set
    }

    pub fn public_key_len(&self) -> usize {
        match &self.inner {
            XmssmtKeyPairInner::Sha2_20_2(kp) => kp.verifying_key().as_ref().len(),
            XmssmtKeyPairInner::Sha2_20_4(kp) => kp.verifying_key().as_ref().len(),
            XmssmtKeyPairInner::Sha2_40_2(kp) => kp.verifying_key().as_ref().len(),
        }
    }

    pub fn secret_key_len(&mut self) -> usize {
        match &mut self.inner {
            XmssmtKeyPairInner::Sha2_20_2(kp) => kp.signing_key().as_ref().len(),
            XmssmtKeyPairInner::Sha2_20_4(kp) => kp.signing_key().as_ref().len(),
            XmssmtKeyPairInner::Sha2_40_2(kp) => kp.signing_key().as_ref().len(),
        }
    }

    /// Sign a message, returning the detached signature bytes.
    /// XMSS^MT is stateful: the signing key is mutated.
    pub fn sign(&mut self, message: &[u8]) -> Result<XmssmtSignature, XmssmtError> {
        let sig_bytes = match &mut self.inner {
            XmssmtKeyPairInner::Sha2_20_2(kp) => {
                let sig = kp
                    .signing_key()
                    .sign_detached(message)
                    .map_err(|e| XmssmtError::SignFailed(e.to_string()))?;
                sig.as_ref().to_vec()
            }
            XmssmtKeyPairInner::Sha2_20_4(kp) => {
                let sig = kp
                    .signing_key()
                    .sign_detached(message)
                    .map_err(|e| XmssmtError::SignFailed(e.to_string()))?;
                sig.as_ref().to_vec()
            }
            XmssmtKeyPairInner::Sha2_40_2(kp) => {
                let sig = kp
                    .signing_key()
                    .sign_detached(message)
                    .map_err(|e| XmssmtError::SignFailed(e.to_string()))?;
                sig.as_ref().to_vec()
            }
        };

        Ok(XmssmtSignature {
            bytes: sig_bytes,
            param_set: self.param_set,
        })
    }

    /// Verify a detached signature against a message.
    pub fn verify(&self, message: &[u8], signature: &XmssmtSignature) -> Result<bool, XmssmtError> {
        if signature.param_set != self.param_set {
            return Err(XmssmtError::MismatchedParamSet {
                expected: self.param_set,
                got: signature.param_set,
            });
        }

        match &self.inner {
            XmssmtKeyPairInner::Sha2_20_2(kp) => {
                verify_detached::<XmssMtSha2_20_2_256>(kp, message, &signature.bytes)
            }
            XmssmtKeyPairInner::Sha2_20_4(kp) => {
                verify_detached::<XmssMtSha2_20_4_256>(kp, message, &signature.bytes)
            }
            XmssmtKeyPairInner::Sha2_40_2(kp) => {
                verify_detached::<XmssMtSha2_40_2_256>(kp, message, &signature.bytes)
            }
        }
    }
}

fn verify_detached<P: XmssParameter>(
    kp: &KeyPair<P>,
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, XmssmtError> {
    let sig = rustcrypto_xmss::DetachedSignature::<P>::try_from(sig_bytes)
        .map_err(|e| XmssmtError::DeserializationFailed(e.to_string()))?;
    match kp.verifying_key().verify_detached(&sig, message) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[derive(Clone, Debug)]
pub struct XmssmtSignature {
    bytes: Vec<u8>,
    param_set: XmssmtParamSet,
}

impl XmssmtSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct XmssmtSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct XmssmtScheme {
    param_set: XmssmtParamSet,
}

impl Default for XmssmtScheme {
    fn default() -> Self {
        Self::new(XmssmtParamSet::Sha2_20_2_256)
    }
}

impl XmssmtScheme {
    pub const fn new(param_set: XmssmtParamSet) -> Self {
        Self { param_set }
    }

    pub const fn param_set(self) -> XmssmtParamSet {
        self.param_set
    }

    pub const fn algorithm_name(self) -> &'static str {
        "XMSS^MT"
    }

    pub const fn backend_name(self) -> &'static str {
        "RustCrypto xmss (pure Rust)"
    }

    pub fn sizes(self) -> Result<XmssmtSizes, XmssmtError> {
        match self.param_set {
            XmssmtParamSet::Sha2_20_2_256 => Ok(XmssmtSizes {
                public_key_bytes: XmssMtSha2_20_2_256::VK_LEN,
                secret_key_bytes: XmssMtSha2_20_2_256::SK_LEN,
                signature_bytes: XmssMtSha2_20_2_256::SIG_LEN,
            }),
            XmssmtParamSet::Sha2_20_4_256 => Ok(XmssmtSizes {
                public_key_bytes: XmssMtSha2_20_4_256::VK_LEN,
                secret_key_bytes: XmssMtSha2_20_4_256::SK_LEN,
                signature_bytes: XmssMtSha2_20_4_256::SIG_LEN,
            }),
            XmssmtParamSet::Sha2_40_2_256 => Ok(XmssmtSizes {
                public_key_bytes: XmssMtSha2_40_2_256::VK_LEN,
                secret_key_bytes: XmssMtSha2_40_2_256::SK_LEN,
                signature_bytes: XmssMtSha2_40_2_256::SIG_LEN,
            }),
        }
    }

    pub fn max_signatures_per_key(self) -> Result<u64, XmssmtError> {
        let height = self.param_set.total_tree_height();
        1u64.checked_shl(height)
            .ok_or(XmssmtError::InvalidHeight(height))
    }

    pub fn keypair(self) -> Result<XmssmtKeyPair, XmssmtError> {
        let mut rng = rand::rng();

        let inner = match self.param_set {
            XmssmtParamSet::Sha2_20_2_256 => {
                let kp = KeyPair::<XmssMtSha2_20_2_256>::generate(&mut rng)
                    .map_err(|e| XmssmtError::KeygenFailed(e.to_string()))?;
                XmssmtKeyPairInner::Sha2_20_2(kp)
            }
            XmssmtParamSet::Sha2_20_4_256 => {
                let kp = KeyPair::<XmssMtSha2_20_4_256>::generate(&mut rng)
                    .map_err(|e| XmssmtError::KeygenFailed(e.to_string()))?;
                XmssmtKeyPairInner::Sha2_20_4(kp)
            }
            XmssmtParamSet::Sha2_40_2_256 => {
                let kp = KeyPair::<XmssMtSha2_40_2_256>::generate(&mut rng)
                    .map_err(|e| XmssmtError::KeygenFailed(e.to_string()))?;
                XmssmtKeyPairInner::Sha2_40_2(kp)
            }
        };

        Ok(XmssmtKeyPair {
            inner,
            param_set: self.param_set,
        })
    }
}

/// Measure wall-clock time of a closure.
pub fn measure_time<T, F>(operation: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

#[derive(Debug)]
pub enum XmssmtError {
    UnsupportedParamSet(String),
    InvalidHeight(u32),
    MismatchedParamSet {
        expected: XmssmtParamSet,
        got: XmssmtParamSet,
    },
    KeygenFailed(String),
    SignFailed(String),
    DeserializationFailed(String),
}

impl fmt::Display for XmssmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedParamSet(param_set) => {
                write!(f, "unsupported XMSS^MT parameter set: {param_set}")
            }
            Self::InvalidHeight(height) => {
                write!(f, "invalid XMSS^MT total tree height: {height}")
            }
            Self::MismatchedParamSet { expected, got } => {
                write!(
                    f,
                    "mismatched XMSS^MT parameter set: expected {}, got {}",
                    expected.as_str(),
                    got.as_str()
                )
            }
            Self::KeygenFailed(msg) => write!(f, "XMSS^MT key generation failed: {msg}"),
            Self::SignFailed(msg) => write!(f, "XMSS^MT signing failed: {msg}"),
            Self::DeserializationFailed(msg) => {
                write!(f, "XMSS^MT deserialization failed: {msg}")
            }
        }
    }
}

impl Error for XmssmtError {}

#[cfg(test)]
mod tests {
    use super::{XmssmtParamSet, XmssmtScheme};
    use rustcrypto_xmss::{XmssMtSha2_20_2_256, XmssSha2_20_256, XmssParameter};

    #[test]
    fn sign_and_verify_roundtrip() {
        let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);
        let message = b"xmssmt-roundtrip-test";

        let mut kp = scheme.keypair().expect("keypair must succeed");
        let signature = kp.sign(message).expect("sign must succeed");

        let is_valid = kp
            .verify(message, &signature)
            .expect("verify call must succeed");

        assert!(is_valid, "signature must verify");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);

        let mut kp = scheme.keypair().expect("keypair must succeed");
        let signature = kp.sign(b"message-a").expect("sign must succeed");

        let is_valid = kp
            .verify(b"message-b", &signature)
            .expect("verify call must succeed");

        assert!(!is_valid, "signature must fail for a different message");
    }

    #[test]
    fn default_signature_matches_xmssmt_parameter_type() {
        let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);
        let mut kp = scheme.keypair().expect("keypair must succeed");
        let signature = kp.sign(b"xmssmt-signature-type").expect("sign must succeed");

        assert_eq!(signature.len(), XmssMtSha2_20_2_256::SIG_LEN);
        assert_ne!(signature.len(), XmssSha2_20_256::SIG_LEN);
    }
}
