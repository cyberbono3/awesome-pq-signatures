use std::error::Error;
use std::ffi::{c_uint, c_ulonglong};
use std::fmt;
use std::str::FromStr;

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

const XMSS_OID_BYTES: usize = 4;

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
        "xmss-reference (C FFI)"
    }

    pub fn sizes(self) -> Result<XmssSizes, XmssError> {
        let params = parse_params(self.param_set.oid())?;
        Ok(XmssSizes {
            public_key_bytes: params.pk_bytes as usize + XMSS_OID_BYTES,
            secret_key_bytes: params.sk_bytes as usize + XMSS_OID_BYTES,
            signature_bytes: params.sig_bytes as usize,
        })
    }

    pub fn max_signatures_per_key(self) -> Result<u64, XmssError> {
        let params = parse_params(self.param_set.oid())?;
        let height = params.full_height;
        1u64.checked_shl(height)
            .ok_or(XmssError::InvalidHeight(height))
    }

    pub fn keypair(self) -> Result<(XmssPublicKey, XmssSecretKey), XmssError> {
        let sizes = self.sizes()?;
        let mut public_key = vec![0_u8; sizes.public_key_bytes];
        let mut secret_key = vec![0_u8; sizes.secret_key_bytes];

        // SAFETY: Buffers are valid and sized according to xmss_parse_oid for this OID.
        let result = unsafe {
            ffi::xmss_keypair(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
                self.param_set.oid(),
            )
        };

        if result != 0 {
            return Err(XmssError::FfiCallFailed("xmss_keypair"));
        }

        Ok((
            XmssPublicKey {
                bytes: public_key,
                param_set: self.param_set,
            },
            XmssSecretKey {
                bytes: secret_key,
                param_set: self.param_set,
            },
        ))
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

        let sizes = self.sizes()?;
        if secret_key.bytes.len() != sizes.secret_key_bytes {
            return Err(XmssError::InvalidSecretKeySize {
                expected: sizes.secret_key_bytes,
                actual: secret_key.bytes.len(),
            });
        }

        let mut signed_message =
            vec![0_u8; sizes.signature_bytes + message.len()];
        let mut signed_message_len: c_ulonglong = 0;

        // SAFETY: Pointers are valid and mutable where required.
        let result = unsafe {
            ffi::xmss_sign(
                secret_key.bytes.as_mut_ptr(),
                signed_message.as_mut_ptr(),
                &mut signed_message_len,
                message.as_ptr(),
                message.len() as c_ulonglong,
            )
        };

        if result != 0 {
            return Err(XmssError::FfiCallFailed("xmss_sign"));
        }

        let signed_message_len = signed_message_len as usize;
        if signed_message_len < message.len() {
            return Err(XmssError::MalformedSignedMessage {
                signed_message_len,
                message_len: message.len(),
            });
        }

        let signature_len = signed_message_len - message.len();
        if signature_len != sizes.signature_bytes {
            return Err(XmssError::InvalidSignatureSize {
                expected: sizes.signature_bytes,
                actual: signature_len,
            });
        }

        Ok(XmssSignature {
            bytes: signed_message[..signature_len].to_vec(),
            param_set: self.param_set,
        })
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

        let sizes = self.sizes()?;
        if public_key.bytes.len() != sizes.public_key_bytes {
            return Err(XmssError::InvalidPublicKeySize {
                expected: sizes.public_key_bytes,
                actual: public_key.bytes.len(),
            });
        }
        if signature.bytes.len() != sizes.signature_bytes {
            return Err(XmssError::InvalidSignatureSize {
                expected: sizes.signature_bytes,
                actual: signature.bytes.len(),
            });
        }

        let mut signed_message =
            Vec::with_capacity(signature.bytes.len() + message.len());
        signed_message.extend_from_slice(&signature.bytes);
        signed_message.extend_from_slice(message);

        let mut recovered_message = vec![0_u8; signed_message.len()];
        let mut recovered_message_len: c_ulonglong = 0;

        // SAFETY: Buffers are valid for FFI call.
        let result = unsafe {
            ffi::xmss_sign_open(
                recovered_message.as_mut_ptr(),
                &mut recovered_message_len,
                signed_message.as_ptr(),
                signed_message.len() as c_ulonglong,
                public_key.bytes.as_ptr(),
            )
        };

        if result != 0 {
            return Ok(false);
        }

        let recovered_message_len = recovered_message_len as usize;
        if recovered_message_len != message.len() {
            return Ok(false);
        }

        Ok(recovered_message[..recovered_message_len] == *message)
    }
}

#[derive(Debug)]
pub enum XmssError {
    UnsupportedParamSet(String),
    InvalidHeight(c_uint),
    InvalidPublicKeySize {
        expected: usize,
        actual: usize,
    },
    InvalidSecretKeySize {
        expected: usize,
        actual: usize,
    },
    InvalidSignatureSize {
        expected: usize,
        actual: usize,
    },
    MalformedSignedMessage {
        signed_message_len: usize,
        message_len: usize,
    },
    MismatchedParamSet {
        expected: XmssParamSet,
        got: XmssParamSet,
    },
    FfiCallFailed(&'static str),
}

impl fmt::Display for XmssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedParamSet(param_set) => {
                write!(f, "unsupported XMSS parameter set: {param_set}")
            }
            Self::InvalidHeight(height) => write!(f, "invalid XMSS tree height: {height}"),
            Self::InvalidPublicKeySize { expected, actual } => {
                write!(f, "invalid public key size: expected {expected}, got {actual}")
            }
            Self::InvalidSecretKeySize { expected, actual } => {
                write!(f, "invalid secret key size: expected {expected}, got {actual}")
            }
            Self::InvalidSignatureSize { expected, actual } => {
                write!(f, "invalid signature size: expected {expected}, got {actual}")
            }
            Self::MalformedSignedMessage {
                signed_message_len,
                message_len,
            } => write!(
                f,
                "malformed signed message buffer: signed_message_len={signed_message_len}, message_len={message_len}"
            ),
            Self::MismatchedParamSet { expected, got } => {
                write!(
                    f,
                    "mismatched XMSS parameter set: expected {}, got {}",
                    expected.as_str(),
                    got.as_str()
                )
            }
            Self::FfiCallFailed(name) => write!(f, "FFI call failed: {name}"),
        }
    }
}

impl Error for XmssError {}

fn parse_params(oid: u32) -> Result<ffi::XmssParams, XmssError> {
    let mut params = ffi::XmssParams::default();

    // SAFETY: `params` is a valid mutable pointer for the duration of the call.
    let result = unsafe { ffi::xmss_parse_oid(&mut params, oid) };
    if result != 0 {
        return Err(XmssError::FfiCallFailed("xmss_parse_oid"));
    }

    Ok(params)
}

mod ffi {
    use std::ffi::{c_int, c_uchar, c_uint, c_ulonglong};

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct XmssParams {
        pub func: c_uint,
        pub n: c_uint,
        pub padding_len: c_uint,
        pub wots_w: c_uint,
        pub wots_log_w: c_uint,
        pub wots_len1: c_uint,
        pub wots_len2: c_uint,
        pub wots_len: c_uint,
        pub wots_sig_bytes: c_uint,
        pub full_height: c_uint,
        pub tree_height: c_uint,
        pub d: c_uint,
        pub index_bytes: c_uint,
        pub sig_bytes: c_uint,
        pub pk_bytes: c_uint,
        pub sk_bytes: c_ulonglong,
        pub bds_k: c_uint,
    }

    unsafe extern "C" {
        pub fn xmss_parse_oid(params: *mut XmssParams, oid: c_uint) -> c_int;

        pub fn xmss_keypair(
            pk: *mut c_uchar,
            sk: *mut c_uchar,
            oid: c_uint,
        ) -> c_int;

        pub fn xmss_sign(
            sk: *mut c_uchar,
            sm: *mut c_uchar,
            smlen: *mut c_ulonglong,
            m: *const c_uchar,
            mlen: c_ulonglong,
        ) -> c_int;

        pub fn xmss_sign_open(
            m: *mut c_uchar,
            mlen: *mut c_ulonglong,
            sm: *const c_uchar,
            smlen: c_ulonglong,
            pk: *const c_uchar,
        ) -> c_int;
    }
}

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
