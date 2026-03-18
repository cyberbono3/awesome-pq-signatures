use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use xmss::{
    DetachedSignature, KeyPair, SigningKey, VerifyingKey, XmssParameter,
    XmssSha2_10_256, XmssSha2_16_256, XmssSha2_20_256,
};

pub const DEFAULT_XMSS_PARAM_SET: XmssParamSet = XmssParamSet::XmssSha2_10_256;
pub const DIVAN_BENCH_MESSAGE_SIZES: [usize; 2] = [32, 1024];

macro_rules! dispatch_param_set {
    ($param_set:expr, $param:ident => $body:expr) => {
        match $param_set {
            XmssParamSet::XmssSha2_10_256 => {
                type $param = XmssSha2_10_256;
                $body
            }
            XmssParamSet::XmssSha2_16_256 => {
                type $param = XmssSha2_16_256;
                $body
            }
            XmssParamSet::XmssSha2_20_256 => {
                type $param = XmssSha2_20_256;
                $body
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmssParamSet {
    XmssSha2_10_256,
    XmssSha2_16_256,
    XmssSha2_20_256,
}

impl XmssParamSet {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XmssSha2_10_256 => "XMSS-SHA2_10_256",
            Self::XmssSha2_16_256 => "XMSS-SHA2_16_256",
            Self::XmssSha2_20_256 => "XMSS-SHA2_20_256",
        }
    }

    #[must_use]
    pub const fn oid(self) -> u32 {
        match self {
            Self::XmssSha2_10_256 => 0x0000_0001,
            Self::XmssSha2_16_256 => 0x0000_0002,
            Self::XmssSha2_20_256 => 0x0000_0003,
        }
    }

    #[must_use]
    pub const fn tree_height(self) -> u32 {
        match self {
            Self::XmssSha2_10_256 => 10,
            Self::XmssSha2_16_256 => 16,
            Self::XmssSha2_20_256 => 20,
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::XmssSha2_10_256,
            Self::XmssSha2_16_256,
            Self::XmssSha2_20_256,
        ]
    }
}

impl FromStr for XmssParamSet {
    type Err = XmssError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "XMSS-SHA2_10_256" => Ok(Self::XmssSha2_10_256),
            "XMSS-SHA2_16_256" => Ok(Self::XmssSha2_16_256),
            "XMSS-SHA2_20_256" => Ok(Self::XmssSha2_20_256),
            _ => Err(XmssError::UnsupportedParamSet(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct XmssPublicKey {
    bytes: Vec<u8>,
    param_set: XmssParamSet,
}

impl XmssPublicKey {
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

#[derive(Clone, Debug)]
pub struct XmssSecretKey {
    bytes: Vec<u8>,
    param_set: XmssParamSet,
}

impl XmssSecretKey {
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

#[derive(Clone, Debug)]
pub struct XmssSignature {
    bytes: Vec<u8>,
    param_set: XmssParamSet,
}

impl XmssSignature {
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
pub struct XmssSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct XmssBenchmarkReport {
    pub display_name: String,
    pub param_set: XmssParamSet,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub signature_size: usize,
    pub verified: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct XmssScheme {
    param_set: XmssParamSet,
}

impl Default for XmssScheme {
    fn default() -> Self {
        Self::new(DEFAULT_XMSS_PARAM_SET)
    }
}

impl XmssScheme {
    #[must_use]
    pub const fn new(param_set: XmssParamSet) -> Self {
        Self { param_set }
    }

    #[must_use]
    pub const fn param_set(self) -> XmssParamSet {
        self.param_set
    }

    #[must_use]
    pub const fn algorithm_name(self) -> &'static str {
        "XMSS"
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
    pub fn sizes(self) -> Result<XmssSizes, XmssError> {
        dispatch_param_set!(self.param_set, Param => Ok(XmssSizes {
            public_key_bytes: Param::VK_LEN,
            secret_key_bytes: Param::SK_LEN,
            signature_bytes: Param::SIG_LEN,
        }))
    }

    /// # Errors
    ///
    /// Returns an error if the XMSS tree height overflows the `u64`
    /// calculation used for the maximum signature count.
    pub fn max_signatures_per_key(self) -> Result<u64, XmssError> {
        let height = self.param_set.tree_height();
        1u64.checked_shl(height)
            .ok_or(XmssError::InvalidHeight(height))
    }

    /// # Errors
    ///
    /// Returns an error if key generation fails for the selected XMSS
    /// parameter set.
    pub fn keypair(self) -> Result<(XmssPublicKey, XmssSecretKey), XmssError> {
        let mut rng = rand::rng();
        dispatch_param_set!(self.param_set, Param => {
            let keypair = KeyPair::<Param>::generate(&mut rng)
                .map_err(|e| XmssError::KeygenFailed(e.to_string()))?;
            Ok(extract_keys(keypair, self.param_set))
        })
    }

    /// # Errors
    ///
    /// Returns an error if the secret key belongs to a different parameter
    /// set or if the underlying XMSS signing step fails.
    pub fn sign(
        self,
        message: &[u8],
        secret_key: &mut XmssSecretKey,
    ) -> Result<XmssSignature, XmssError> {
        if secret_key.param_set != self.param_set {
            return Err(XmssError::MismatchedParamSet {
                expected: self.param_set,
                got: secret_key.param_set,
            });
        }

        dispatch_param_set!(self.param_set, Param => sign_with::<Param>(
            message,
            secret_key,
            self.param_set
        ))
    }

    /// # Errors
    ///
    /// Returns an error if the public key or signature belongs to a different
    /// parameter set or if deserialization fails.
    pub fn verify(
        self,
        message: &[u8],
        signature: &XmssSignature,
        public_key: &XmssPublicKey,
    ) -> Result<bool, XmssError> {
        if signature.param_set != self.param_set {
            return Err(XmssError::MismatchedParamSet {
                expected: self.param_set,
                got: signature.param_set,
            });
        }
        if public_key.param_set != self.param_set {
            return Err(XmssError::MismatchedParamSet {
                expected: self.param_set,
                got: public_key.param_set,
            });
        }

        dispatch_param_set!(self.param_set, Param => verify_with::<Param>(
            message,
            signature,
            public_key
        ))
    }

    /// # Errors
    ///
    /// Returns an error if any step of the key generation, signing, or
    /// verification flow fails.
    pub fn benchmark_report(
        self,
        message: &[u8],
    ) -> Result<XmssBenchmarkReport, XmssError> {
        let display_name = self.display_name();
        let (keypair, keygen_duration) = measure_time(|| self.keypair());
        let (public_key, mut secret_key) = keypair?;
        let (signature_result, sign_duration) =
            measure_time(|| self.sign(message, &mut secret_key));
        let signature = signature_result?;

        let secret_key = secret_key;
        let (verified_result, verify_duration) =
            measure_time(|| self.verify(message, &signature, &public_key));
        let verified = verified_result?;

        Ok(XmssBenchmarkReport {
            display_name,
            param_set: self.param_set(),
            keygen_duration,
            sign_duration,
            verify_duration,
            public_key_size: public_key.len(),
            secret_key_size: secret_key.len(),
            signature_size: signature.len(),
            verified,
        })
    }
}

#[must_use]
pub const fn default_benchmark_scheme() -> XmssScheme {
    XmssScheme::new(DEFAULT_XMSS_PARAM_SET)
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

fn extract_keys<P: XmssParameter>(
    mut kp: KeyPair<P>,
    param_set: XmssParamSet,
) -> (XmssPublicKey, XmssSecretKey) {
    let vk_bytes = kp.verifying_key().as_ref().to_vec();
    let sk_bytes = kp.signing_key().as_ref().to_vec();

    (
        XmssPublicKey {
            bytes: vk_bytes,
            param_set,
        },
        XmssSecretKey {
            bytes: sk_bytes,
            param_set,
        },
    )
}

fn sign_with<P: XmssParameter>(
    message: &[u8],
    secret_key: &mut XmssSecretKey,
    param_set: XmssParamSet,
) -> Result<XmssSignature, XmssError> {
    let mut sk = SigningKey::<P>::try_from(secret_key.bytes.as_slice())
        .map_err(|e| XmssError::DeserializationFailed(e.to_string()))?;

    let sig = sk
        .sign_detached(message)
        .map_err(|e| XmssError::SignFailed(e.to_string()))?;

    // Update the secret key state (XMSS is stateful)
    secret_key.bytes = sk.as_ref().to_vec();

    Ok(XmssSignature {
        bytes: sig.as_ref().to_vec(),
        param_set,
    })
}

fn verify_with<P: XmssParameter>(
    message: &[u8],
    signature: &XmssSignature,
    public_key: &XmssPublicKey,
) -> Result<bool, XmssError> {
    let vk = VerifyingKey::<P>::try_from(public_key.bytes.as_slice())
        .map_err(|e| XmssError::DeserializationFailed(e.to_string()))?;

    let sig = DetachedSignature::<P>::try_from(signature.bytes.as_slice())
        .map_err(|e| XmssError::DeserializationFailed(e.to_string()))?;

    match vk.verify_detached(&sig, message) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[derive(Debug)]
pub enum XmssError {
    UnsupportedParamSet(String),
    InvalidHeight(u32),
    MismatchedParamSet {
        expected: XmssParamSet,
        got: XmssParamSet,
    },
    KeygenFailed(String),
    SignFailed(String),
    DeserializationFailed(String),
}

impl fmt::Display for XmssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedParamSet(param_set) => {
                write!(f, "unsupported XMSS parameter set: {param_set}")
            }
            Self::InvalidHeight(height) => {
                write!(f, "invalid XMSS tree height: {height}")
            }
            Self::MismatchedParamSet { expected, got } => {
                write!(
                    f,
                    "mismatched XMSS parameter set: expected {}, got {}",
                    expected.as_str(),
                    got.as_str()
                )
            }
            Self::KeygenFailed(msg) => {
                write!(f, "XMSS key generation failed: {msg}")
            }
            Self::SignFailed(msg) => write!(f, "XMSS signing failed: {msg}"),
            Self::DeserializationFailed(msg) => {
                write!(f, "XMSS deserialization failed: {msg}")
            }
        }
    }
}

impl Error for XmssError {}

#[cfg(test)]
mod tests {
    use super::{XmssParamSet, XmssScheme};

    #[test]
    fn sign_and_verify_roundtrip() {
        let scheme = XmssScheme::new(XmssParamSet::XmssSha2_10_256);
        let message = b"xmss-roundtrip-test";

        let (public_key, mut secret_key) =
            scheme.keypair().expect("keypair must succeed");
        let signature = scheme
            .sign(message, &mut secret_key)
            .expect("sign must succeed");

        let is_valid = scheme
            .verify(message, &signature, &public_key)
            .expect("verify call must succeed");

        assert!(is_valid, "signature must verify");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let scheme = XmssScheme::new(XmssParamSet::XmssSha2_10_256);

        let (public_key, mut secret_key) =
            scheme.keypair().expect("keypair must succeed");
        let signature = scheme
            .sign(b"message-a", &mut secret_key)
            .expect("sign must succeed");

        let is_valid = scheme
            .verify(b"message-b", &signature, &public_key)
            .expect("verify call must succeed");

        assert!(!is_valid, "signature must fail for a different message");
    }
}
