use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use xmss::{
    DetachedSignature, KeyPair, SigningKey, VerifyingKey, XmssParameter, XmssSha2_10_256,
    XmssSha2_16_256, XmssSha2_20_256,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmssParamSet {
    XmssSha2_10_256,
    XmssSha2_16_256,
    XmssSha2_20_256,
}

impl XmssParamSet {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XmssSha2_10_256 => "XMSS-SHA2_10_256",
            Self::XmssSha2_16_256 => "XMSS-SHA2_16_256",
            Self::XmssSha2_20_256 => "XMSS-SHA2_20_256",
        }
    }

    pub const fn oid(self) -> u32 {
        match self {
            Self::XmssSha2_10_256 => 0x0000_0001,
            Self::XmssSha2_16_256 => 0x0000_0002,
            Self::XmssSha2_20_256 => 0x0000_0003,
        }
    }

    pub const fn tree_height(self) -> u32 {
        match self {
            Self::XmssSha2_10_256 => 10,
            Self::XmssSha2_16_256 => 16,
            Self::XmssSha2_20_256 => 20,
        }
    }

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

#[derive(Clone, Debug)]
pub struct XmssSecretKey {
    bytes: Vec<u8>,
    param_set: XmssParamSet,
}

impl XmssSecretKey {
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

#[derive(Clone, Debug)]
pub struct XmssSignature {
    bytes: Vec<u8>,
    param_set: XmssParamSet,
}

impl XmssSignature {
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
pub struct XmssSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct XmssScheme {
    param_set: XmssParamSet,
}

impl Default for XmssScheme {
    fn default() -> Self {
        Self::new(XmssParamSet::XmssSha2_10_256)
    }
}

impl XmssScheme {
    pub const fn new(param_set: XmssParamSet) -> Self {
        Self { param_set }
    }

    pub const fn param_set(self) -> XmssParamSet {
        self.param_set
    }

    pub const fn algorithm_name(self) -> &'static str {
        "XMSS"
    }

    pub const fn backend_name(self) -> &'static str {
        "RustCrypto xmss (pure Rust)"
    }

    pub fn sizes(self) -> Result<XmssSizes, XmssError> {
        match self.param_set {
            XmssParamSet::XmssSha2_10_256 => Ok(XmssSizes {
                public_key_bytes: XmssSha2_10_256::VK_LEN,
                secret_key_bytes: XmssSha2_10_256::SK_LEN,
                signature_bytes: XmssSha2_10_256::SIG_LEN,
            }),
            XmssParamSet::XmssSha2_16_256 => Ok(XmssSizes {
                public_key_bytes: XmssSha2_16_256::VK_LEN,
                secret_key_bytes: XmssSha2_16_256::SK_LEN,
                signature_bytes: XmssSha2_16_256::SIG_LEN,
            }),
            XmssParamSet::XmssSha2_20_256 => Ok(XmssSizes {
                public_key_bytes: XmssSha2_20_256::VK_LEN,
                secret_key_bytes: XmssSha2_20_256::SK_LEN,
                signature_bytes: XmssSha2_20_256::SIG_LEN,
            }),
        }
    }

    pub fn max_signatures_per_key(self) -> Result<u64, XmssError> {
        let height = self.param_set.tree_height();
        1u64.checked_shl(height)
            .ok_or(XmssError::InvalidHeight(height))
    }

    pub fn keypair(self) -> Result<(XmssPublicKey, XmssSecretKey), XmssError> {
        let mut rng = rand::rng();

        match self.param_set {
            XmssParamSet::XmssSha2_10_256 => {
                let kp = KeyPair::<XmssSha2_10_256>::generate(&mut rng)
                    .map_err(|e| XmssError::KeygenFailed(e.to_string()))?;
                Ok(extract_keys(kp, self.param_set))
            }
            XmssParamSet::XmssSha2_16_256 => {
                let kp = KeyPair::<XmssSha2_16_256>::generate(&mut rng)
                    .map_err(|e| XmssError::KeygenFailed(e.to_string()))?;
                Ok(extract_keys(kp, self.param_set))
            }
            XmssParamSet::XmssSha2_20_256 => {
                let kp = KeyPair::<XmssSha2_20_256>::generate(&mut rng)
                    .map_err(|e| XmssError::KeygenFailed(e.to_string()))?;
                Ok(extract_keys(kp, self.param_set))
            }
        }
    }

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

        match self.param_set {
            XmssParamSet::XmssSha2_10_256 => {
                sign_with::<XmssSha2_10_256>(message, secret_key, self.param_set)
            }
            XmssParamSet::XmssSha2_16_256 => {
                sign_with::<XmssSha2_16_256>(message, secret_key, self.param_set)
            }
            XmssParamSet::XmssSha2_20_256 => {
                sign_with::<XmssSha2_20_256>(message, secret_key, self.param_set)
            }
        }
    }

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

        match self.param_set {
            XmssParamSet::XmssSha2_10_256 => {
                verify_with::<XmssSha2_10_256>(message, signature, public_key)
            }
            XmssParamSet::XmssSha2_16_256 => {
                verify_with::<XmssSha2_16_256>(message, signature, public_key)
            }
            XmssParamSet::XmssSha2_20_256 => {
                verify_with::<XmssSha2_20_256>(message, signature, public_key)
            }
        }
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
            Self::KeygenFailed(msg) => write!(f, "XMSS key generation failed: {msg}"),
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

        let (public_key, mut secret_key) = scheme.keypair().expect("keypair must succeed");
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

        let (public_key, mut secret_key) = scheme.keypair().expect("keypair must succeed");
        let signature = scheme
            .sign(b"message-a", &mut secret_key)
            .expect("sign must succeed");

        let is_valid = scheme
            .verify(b"message-b", &signature, &public_key)
            .expect("verify call must succeed");

        assert!(!is_valid, "signature must fail for a different message");
    }
}
