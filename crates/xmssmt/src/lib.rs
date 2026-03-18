use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use rustcrypto_xmss::{
    DetachedSignature, KeyPair, XmssMtSha2_20_2_256, XmssMtSha2_20_4_256,
    XmssMtSha2_40_2_256, XmssParameter,
};

pub const DEFAULT_XMSSMT_PARAM_SET: XmssmtParamSet = XmssmtParamSet::Sha2_20_2_256;
pub const DIVAN_BENCH_MESSAGE_SIZES: [usize; 2] = [32, 1024];

macro_rules! dispatch_param_set {
    ($param_set:expr, $param:ident => $body:expr) => {
        match $param_set {
            XmssmtParamSet::Sha2_20_2_256 => {
                type $param = XmssMtSha2_20_2_256;
                $body
            }
            XmssmtParamSet::Sha2_20_4_256 => {
                type $param = XmssMtSha2_20_4_256;
                $body
            }
            XmssmtParamSet::Sha2_40_2_256 => {
                type $param = XmssMtSha2_40_2_256;
                $body
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmssmtParamSet {
    Sha2_20_2_256,
    Sha2_20_4_256,
    Sha2_40_2_256,
}

impl XmssmtParamSet {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha2_20_2_256 => "XMSSMT-SHA2_20/2_256",
            Self::Sha2_20_4_256 => "XMSSMT-SHA2_20/4_256",
            Self::Sha2_40_2_256 => "XMSSMT-SHA2_40/2_256",
        }
    }

    #[must_use]
    pub const fn oid(self) -> u32 {
        match self {
            Self::Sha2_20_2_256 => 0x0001_0001,
            Self::Sha2_20_4_256 => 0x0001_0002,
            Self::Sha2_40_2_256 => 0x0001_0003,
        }
    }

    #[must_use]
    pub const fn total_tree_height(self) -> u32 {
        match self {
            Self::Sha2_20_2_256 | Self::Sha2_20_4_256 => 20,
            Self::Sha2_40_2_256 => 40,
        }
    }

    #[must_use]
    pub const fn depth(self) -> u32 {
        match self {
            Self::Sha2_20_4_256 => 4,
            Self::Sha2_20_2_256 | Self::Sha2_40_2_256 => 2,
        }
    }

    #[must_use]
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

impl XmssmtKeyPairInner {
    fn public_key_len(&self) -> usize {
        match self {
            Self::Sha2_20_2(keypair) => keypair.verifying_key().as_ref().len(),
            Self::Sha2_20_4(keypair) => keypair.verifying_key().as_ref().len(),
            Self::Sha2_40_2(keypair) => keypair.verifying_key().as_ref().len(),
        }
    }

    fn secret_key_len(&mut self) -> usize {
        match self {
            Self::Sha2_20_2(keypair) => keypair.signing_key().as_ref().len(),
            Self::Sha2_20_4(keypair) => keypair.signing_key().as_ref().len(),
            Self::Sha2_40_2(keypair) => keypair.signing_key().as_ref().len(),
        }
    }

    fn sign_detached(&mut self, message: &[u8]) -> Result<Vec<u8>, XmssmtError> {
        match self {
            Self::Sha2_20_2(keypair) => sign_detached_with_keypair(keypair, message),
            Self::Sha2_20_4(keypair) => sign_detached_with_keypair(keypair, message),
            Self::Sha2_40_2(keypair) => sign_detached_with_keypair(keypair, message),
        }
    }

    fn verify_detached(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, XmssmtError> {
        match self {
            Self::Sha2_20_2(keypair) => {
                verify_detached_with_keypair(keypair, message, signature)
            }
            Self::Sha2_20_4(keypair) => {
                verify_detached_with_keypair(keypair, message, signature)
            }
            Self::Sha2_40_2(keypair) => {
                verify_detached_with_keypair(keypair, message, signature)
            }
        }
    }
}

impl XmssmtKeyPair {
    #[must_use]
    pub fn param_set(&self) -> XmssmtParamSet {
        self.param_set
    }

    #[must_use]
    pub fn public_key_len(&self) -> usize {
        self.inner.public_key_len()
    }

    #[must_use]
    pub fn secret_key_len(&mut self) -> usize {
        self.inner.secret_key_len()
    }

    /// Sign a message, returning the detached signature bytes.
    /// XMSS^MT is stateful: the signing key is mutated.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying XMSS^MT signing operation fails.
    pub fn sign(&mut self, message: &[u8]) -> Result<XmssmtSignature, XmssmtError> {
        let sig_bytes = self.inner.sign_detached(message)?;

        Ok(XmssmtSignature {
            bytes: sig_bytes,
            param_set: self.param_set,
        })
    }

    /// Verify a detached signature against a message.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature belongs to a different parameter set
    /// or detached signature decoding fails.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &XmssmtSignature,
    ) -> Result<bool, XmssmtError> {
        if signature.param_set != self.param_set {
            return Err(XmssmtError::MismatchedParamSet {
                expected: self.param_set,
                got: signature.param_set,
            });
        }

        self.inner.verify_detached(message, &signature.bytes)
    }
}

fn sign_detached_with_keypair<P: XmssParameter>(
    keypair: &mut KeyPair<P>,
    message: &[u8],
) -> Result<Vec<u8>, XmssmtError> {
    let signature = keypair
        .signing_key()
        .sign_detached(message)
        .map_err(|e| XmssmtError::SignFailed(e.to_string()))?;
    Ok(signature.as_ref().to_vec())
}

fn verify_detached_with_keypair<P: XmssParameter>(
    keypair: &KeyPair<P>,
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, XmssmtError> {
    let signature = DetachedSignature::<P>::try_from(sig_bytes)
        .map_err(|e| XmssmtError::DeserializationFailed(e.to_string()))?;
    match keypair.verifying_key().verify_detached(&signature, message) {
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
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
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

#[derive(Clone, Debug)]
pub struct XmssmtBenchmarkReport {
    pub display_name: String,
    pub param_set: XmssmtParamSet,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub signature_size: usize,
    pub verified: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct XmssmtScheme {
    param_set: XmssmtParamSet,
}

impl Default for XmssmtScheme {
    fn default() -> Self {
        Self::new(DEFAULT_XMSSMT_PARAM_SET)
    }
}

impl XmssmtScheme {
    #[must_use]
    pub const fn new(param_set: XmssmtParamSet) -> Self {
        Self { param_set }
    }

    #[must_use]
    pub const fn param_set(self) -> XmssmtParamSet {
        self.param_set
    }

    #[must_use]
    pub const fn algorithm_name(self) -> &'static str {
        "XMSS^MT"
    }

    #[must_use]
    pub const fn backend_name(self) -> &'static str {
        "RustCrypto xmss (pure Rust)"
    }

    #[must_use]
    pub fn display_name(self) -> String {
        format!("{} ({})", self.param_set().as_str(), self.backend_name())
    }

    /// # Errors
    ///
    /// Returns an error if the selected parameter set cannot provide static
    /// size information.
    pub fn sizes(self) -> Result<XmssmtSizes, XmssmtError> {
        dispatch_param_set!(self.param_set, Param => Ok(XmssmtSizes {
            public_key_bytes: Param::VK_LEN,
            secret_key_bytes: Param::SK_LEN,
            signature_bytes: Param::SIG_LEN,
        }))
    }

    /// # Errors
    ///
    /// Returns an error if the XMSS^MT total tree height overflows the `u64`
    /// calculation used for the maximum signature count.
    pub fn max_signatures_per_key(self) -> Result<u64, XmssmtError> {
        let height = self.param_set.total_tree_height();
        1u64.checked_shl(height)
            .ok_or(XmssmtError::InvalidHeight(height))
    }

    /// # Errors
    ///
    /// Returns an error if key generation fails for the selected XMSS^MT
    /// parameter set.
    pub fn keypair(self) -> Result<XmssmtKeyPair, XmssmtError> {
        let mut rng = rand::rng();

        let inner = match self.param_set {
            XmssmtParamSet::Sha2_20_2_256 => {
                let keypair = KeyPair::<XmssMtSha2_20_2_256>::generate(&mut rng)
                    .map_err(|e| XmssmtError::KeygenFailed(e.to_string()))?;
                XmssmtKeyPairInner::Sha2_20_2(keypair)
            }
            XmssmtParamSet::Sha2_20_4_256 => {
                let keypair = KeyPair::<XmssMtSha2_20_4_256>::generate(&mut rng)
                    .map_err(|e| XmssmtError::KeygenFailed(e.to_string()))?;
                XmssmtKeyPairInner::Sha2_20_4(keypair)
            }
            XmssmtParamSet::Sha2_40_2_256 => {
                let keypair = KeyPair::<XmssMtSha2_40_2_256>::generate(&mut rng)
                    .map_err(|e| XmssmtError::KeygenFailed(e.to_string()))?;
                XmssmtKeyPairInner::Sha2_40_2(keypair)
            }
        };

        Ok(XmssmtKeyPair {
            inner,
            param_set: self.param_set,
        })
    }

    /// # Errors
    ///
    /// Returns an error if any step of the key generation, signing, or
    /// verification flow fails.
    pub fn benchmark_report(
        self,
        message: &[u8],
    ) -> Result<XmssmtBenchmarkReport, XmssmtError> {
        let display_name = self.display_name();
        let (keypair_result, keygen_duration) = measure_time(|| self.keypair());
        let mut keypair = keypair_result?;
        let public_key_size = keypair.public_key_len();
        let secret_key_size = keypair.secret_key_len();

        let (signature_result, sign_duration) = measure_time(|| keypair.sign(message));
        let signature = signature_result?;

        let (verified_result, verify_duration) =
            measure_time(|| keypair.verify(message, &signature));
        let verified = verified_result?;

        Ok(XmssmtBenchmarkReport {
            display_name,
            param_set: self.param_set(),
            keygen_duration,
            sign_duration,
            verify_duration,
            public_key_size,
            secret_key_size,
            signature_size: signature.len(),
            verified,
        })
    }
}

#[must_use]
pub const fn default_benchmark_scheme() -> XmssmtScheme {
    XmssmtScheme::new(DEFAULT_XMSSMT_PARAM_SET)
}

#[must_use]
pub fn benchmark_message(size: usize, fill_byte: u8) -> Vec<u8> {
    vec![fill_byte; size]
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

        let mut keypair = scheme.keypair().expect("keypair must succeed");
        let signature = keypair.sign(message).expect("sign must succeed");

        let is_valid = keypair
            .verify(message, &signature)
            .expect("verify call must succeed");

        assert!(is_valid, "signature must verify");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);

        let mut keypair = scheme.keypair().expect("keypair must succeed");
        let signature = keypair.sign(b"message-a").expect("sign must succeed");

        let is_valid = keypair
            .verify(b"message-b", &signature)
            .expect("verify call must succeed");

        assert!(!is_valid, "signature must fail for a different message");
    }

    #[test]
    fn default_signature_matches_xmssmt_parameter_type() {
        let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);
        let mut keypair = scheme.keypair().expect("keypair must succeed");
        let signature = keypair
            .sign(b"xmssmt-signature-type")
            .expect("sign must succeed");

        assert_eq!(signature.len(), XmssMtSha2_20_2_256::SIG_LEN);
        assert_ne!(signature.len(), XmssSha2_20_256::SIG_LEN);
    }
}
