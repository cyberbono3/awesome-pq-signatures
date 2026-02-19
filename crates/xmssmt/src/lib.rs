use std::alloc::{GlobalAlloc, Layout};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const XMSSMT_L1_NAME: &str = "XMSSMT-L1";
pub const XMSSMT_L3_NAME: &str = "XMSSMT-L3";
pub const XMSSMT_L5_NAME: &str = "XMSSMT-L5";
pub const DEFAULT_PARAM_SET_NAME: &str = XMSSMT_L1_NAME;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmssmtParamSet {
    Level1,
    Level3,
    Level5,
}

impl XmssmtParamSet {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Level1 => XMSSMT_L1_NAME,
            Self::Level3 => XMSSMT_L3_NAME,
            Self::Level5 => XMSSMT_L5_NAME,
        }
    }
}

pub const XMSSMT_PARAM_SETS: [XmssmtParamSet; 3] = [
    XmssmtParamSet::Level1,
    XmssmtParamSet::Level3,
    XmssmtParamSet::Level5,
];

pub fn param_set_by_name(name: &str) -> Option<XmssmtParamSet> {
    match name {
        XMSSMT_L1_NAME => Some(XmssmtParamSet::Level1),
        XMSSMT_L3_NAME => Some(XmssmtParamSet::Level3),
        XMSSMT_L5_NAME => Some(XmssmtParamSet::Level5),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct XmssmtPublicKey {
    bytes: Vec<u8>,
    params: XmssmtParamSet,
}

impl XmssmtPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Clone, Debug)]
pub struct XmssmtSecretKey {
    bytes: Vec<u8>,
    params: XmssmtParamSet,
}

impl XmssmtSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Clone, Debug)]
pub struct XmssmtSignature {
    bytes: Vec<u8>,
    params: XmssmtParamSet,
}

impl XmssmtSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct XmssmtSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct XmssmtScheme {
    params: XmssmtParamSet,
}

impl XmssmtScheme {
    pub fn new(params: XmssmtParamSet) -> Self {
        Self { params }
    }

    pub fn from_param_set_name(name: &str) -> Result<Self, XmssmtError> {
        let params = param_set_by_name(name).ok_or_else(|| {
            XmssmtError::UnknownParamSet {
                name: name.to_owned(),
            }
        })?;
        Ok(Self::new(params))
    }

    pub fn algorithm_name(&self) -> &'static str {
        "XMSSMT"
    }

    pub fn backend_name(&self) -> &'static str {
        "thomwiggers/xmss-rs"
    }

    pub fn param_set_name(&self) -> &'static str {
        self.params.name()
    }

    pub fn signatures_per_key(&self) -> u64 {
        1_u64 << 24
    }

    pub fn sizes(&self) -> XmssmtSizes {
        XmssmtSizes {
            public_key_bytes: public_key_bytes(self.params),
            secret_key_bytes: secret_key_bytes(self.params),
            signature_bytes: signature_bytes(self.params),
        }
    }

    pub fn keypair(&self) -> (XmssmtPublicKey, XmssmtSecretKey) {
        let (public_key, secret_key) = keypair(self.params);
        (
            XmssmtPublicKey {
                bytes: public_key,
                params: self.params,
            },
            XmssmtSecretKey {
                bytes: secret_key,
                params: self.params,
            },
        )
    }

    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &mut XmssmtSecretKey,
    ) -> Result<XmssmtSignature, XmssmtError> {
        self.ensure_secret_key_params(secret_key)?;
        self.ensure_secret_key_len(secret_key)?;

        let signature = sign(self.params, &mut secret_key.bytes, message);
        self.ensure_signature_len(signature.len())?;

        Ok(XmssmtSignature {
            bytes: signature,
            params: self.params,
        })
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &XmssmtSignature,
        public_key: &XmssmtPublicKey,
    ) -> Result<bool, XmssmtError> {
        self.ensure_public_key_params(public_key)?;
        self.ensure_signature_params(signature)?;
        self.ensure_public_key_len(public_key)?;
        self.ensure_signature_len(signature.bytes.len())?;

        Ok(verify(
            self.params,
            message,
            &signature.bytes,
            &public_key.bytes,
        ))
    }

    pub fn public_key_size(&self, public_key: &XmssmtPublicKey) -> usize {
        public_key.byte_len()
    }

    pub fn secret_key_size(&self, secret_key: &XmssmtSecretKey) -> usize {
        secret_key.byte_len()
    }

    pub fn signature_size(&self, signature: &XmssmtSignature) -> usize {
        signature.byte_len()
    }

    fn ensure_secret_key_params(
        &self,
        secret_key: &XmssmtSecretKey,
    ) -> Result<(), XmssmtError> {
        if secret_key.params != self.params {
            return Err(XmssmtError::ParamSetMismatch {
                expected: self.param_set_name(),
                actual: secret_key.params.name(),
            });
        }
        Ok(())
    }

    fn ensure_public_key_params(
        &self,
        public_key: &XmssmtPublicKey,
    ) -> Result<(), XmssmtError> {
        if public_key.params != self.params {
            return Err(XmssmtError::ParamSetMismatch {
                expected: self.param_set_name(),
                actual: public_key.params.name(),
            });
        }
        Ok(())
    }

    fn ensure_signature_params(
        &self,
        signature: &XmssmtSignature,
    ) -> Result<(), XmssmtError> {
        if signature.params != self.params {
            return Err(XmssmtError::ParamSetMismatch {
                expected: self.param_set_name(),
                actual: signature.params.name(),
            });
        }
        Ok(())
    }

    fn ensure_public_key_len(
        &self,
        public_key: &XmssmtPublicKey,
    ) -> Result<(), XmssmtError> {
        let expected = public_key_bytes(self.params);
        let actual = public_key.bytes.len();
        if actual != expected {
            return Err(XmssmtError::InvalidPublicKeyLength {
                expected,
                actual,
            });
        }
        Ok(())
    }

    fn ensure_secret_key_len(
        &self,
        secret_key: &XmssmtSecretKey,
    ) -> Result<(), XmssmtError> {
        let expected = secret_key_bytes(self.params);
        let actual = secret_key.bytes.len();
        if actual != expected {
            return Err(XmssmtError::InvalidSecretKeyLength {
                expected,
                actual,
            });
        }
        Ok(())
    }

    fn ensure_signature_len(&self, actual: usize) -> Result<(), XmssmtError> {
        let expected = signature_bytes(self.params);
        if actual != expected {
            return Err(XmssmtError::InvalidSignatureLength {
                expected,
                actual,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmssmtError {
    UnknownParamSet {
        name: String,
    },
    ParamSetMismatch {
        expected: &'static str,
        actual: &'static str,
    },
    InvalidPublicKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidSecretKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidSignatureLength {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for XmssmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParamSet { name } => {
                write!(f, "unknown XMSSMT param set: {name}")
            }
            Self::ParamSetMismatch { expected, actual } => write!(
                f,
                "parameter set mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidPublicKeyLength { expected, actual } => write!(
                f,
                "invalid XMSSMT public key length: expected {expected}, got {actual}"
            ),
            Self::InvalidSecretKeyLength { expected, actual } => write!(
                f,
                "invalid XMSSMT secret key length: expected {expected}, got {actual}"
            ),
            Self::InvalidSignatureLength { expected, actual } => write!(
                f,
                "invalid XMSSMT signature length: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for XmssmtError {}

pub fn bench_message(size: usize) -> Vec<u8> {
    vec![BENCH_MESSAGE_BYTE; size]
}

pub fn measure_time<T, F>(operation: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

fn keypair(params: XmssmtParamSet) -> (Vec<u8>, Vec<u8>) {
    match params {
        XmssmtParamSet::Level1 => xmss_rs::level1::keypair(),
        XmssmtParamSet::Level3 => xmss_rs::level3::keypair(),
        XmssmtParamSet::Level5 => xmss_rs::level5::keypair(),
    }
}

fn sign(params: XmssmtParamSet, secret_key: &mut [u8], msg: &[u8]) -> Vec<u8> {
    match params {
        XmssmtParamSet::Level1 => xmss_rs::level1::sign(secret_key, msg),
        XmssmtParamSet::Level3 => xmss_rs::level3::sign(secret_key, msg),
        XmssmtParamSet::Level5 => xmss_rs::level5::sign(secret_key, msg),
    }
}

fn verify(
    params: XmssmtParamSet,
    msg: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    match params {
        XmssmtParamSet::Level1 => {
            xmss_rs::level1::verify(msg, signature, public_key)
        }
        XmssmtParamSet::Level3 => {
            xmss_rs::level3::verify(msg, signature, public_key)
        }
        XmssmtParamSet::Level5 => {
            xmss_rs::level5::verify(msg, signature, public_key)
        }
    }
}

fn public_key_bytes(params: XmssmtParamSet) -> usize {
    match params {
        XmssmtParamSet::Level1 => xmss_rs::level1::pk_bytes(),
        XmssmtParamSet::Level3 => xmss_rs::level3::pk_bytes(),
        XmssmtParamSet::Level5 => xmss_rs::level5::pk_bytes(),
    }
}

fn secret_key_bytes(params: XmssmtParamSet) -> usize {
    match params {
        XmssmtParamSet::Level1 => xmss_rs::level1::sk_bytes(),
        XmssmtParamSet::Level3 => xmss_rs::level3::sk_bytes(),
        XmssmtParamSet::Level5 => xmss_rs::level5::sk_bytes(),
    }
}

fn signature_bytes(params: XmssmtParamSet) -> usize {
    match params {
        XmssmtParamSet::Level1 => xmss_rs::level1::sig_bytes(),
        XmssmtParamSet::Level3 => xmss_rs::level3::sig_bytes(),
        XmssmtParamSet::Level5 => xmss_rs::level5::sig_bytes(),
    }
}

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);

pub struct TrackingAllocator<A: GlobalAlloc + Sync + 'static> {
    inner: &'static A,
}

impl<A: GlobalAlloc + Sync + 'static> TrackingAllocator<A> {
    pub const fn new(inner: &'static A) -> Self {
        Self { inner }
    }
}

unsafe impl<A: GlobalAlloc + Sync + 'static> GlobalAlloc
    for TrackingAllocator<A>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            track_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        track_dealloc(layout.size());
    }
}

fn track_alloc(size: usize) {
    let current = ALLOCATED.fetch_add(size, Ordering::SeqCst) + size;
    let baseline = BASELINE.load(Ordering::SeqCst);
    let relative_current = current.saturating_sub(baseline);
    let mut peak = PEAK_ALLOCATED.load(Ordering::SeqCst);

    while relative_current > peak {
        match PEAK_ALLOCATED.compare_exchange_weak(
            peak,
            relative_current,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

fn track_dealloc(size: usize) {
    ALLOCATED.fetch_sub(size, Ordering::SeqCst);
}

pub mod memory {
    use super::{Ordering, ALLOCATED, BASELINE, PEAK_ALLOCATED};

    pub fn reset_peak() {
        let current = ALLOCATED.load(Ordering::SeqCst);
        BASELINE.store(current, Ordering::SeqCst);
        PEAK_ALLOCATED.store(0, Ordering::SeqCst);
    }

    pub fn peak_bytes() -> usize {
        PEAK_ALLOCATED.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, param_set_by_name, XmssmtScheme, BENCH_MESSAGE_BYTE,
        XMSSMT_L1_NAME,
    };

    #[test]
    fn param_set_lookup_works() {
        let found = param_set_by_name(XMSSMT_L1_NAME)
            .expect("known param set resolves");
        assert_eq!(found.name(), XMSSMT_L1_NAME);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let scheme = XmssmtScheme::from_param_set_name(XMSSMT_L1_NAME)
            .expect("param set should resolve");
        let message = b"xmssmt-sign-verify-roundtrip";
        let (public_key, mut secret_key) = scheme.keypair();

        let signature = scheme
            .sign(message, &mut secret_key)
            .expect("sign should succeed");
        let verified = scheme
            .verify(message, &signature, &public_key)
            .expect("verify should succeed");
        assert!(verified, "signature should verify");
    }

    #[test]
    fn verify_fails_for_other_message() {
        let scheme = XmssmtScheme::from_param_set_name(XMSSMT_L1_NAME)
            .expect("param set should resolve");
        let (public_key, mut secret_key) = scheme.keypair();

        let signature = scheme
            .sign(b"message-a", &mut secret_key)
            .expect("sign should succeed");
        let verified = scheme
            .verify(b"message-b", &signature, &public_key)
            .expect("verify should succeed");
        assert!(!verified, "different message should fail verification");
    }

    #[test]
    fn sign_updates_secret_key_state() {
        let scheme = XmssmtScheme::from_param_set_name(XMSSMT_L1_NAME)
            .expect("param set should resolve");
        let (_, mut secret_key) = scheme.keypair();
        let before = secret_key.as_bytes().to_vec();

        let _signature = scheme
            .sign(b"stateful-signing", &mut secret_key)
            .expect("sign should succeed");

        assert_ne!(
            before,
            secret_key.as_bytes(),
            "xmss-rs secret key should update after signing"
        );
    }

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let msg = bench_message(16);
        assert_eq!(msg.len(), 16);
        assert!(msg.iter().all(|b| *b == BENCH_MESSAGE_BYTE));
    }
}
