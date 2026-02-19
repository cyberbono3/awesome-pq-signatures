use getrandom::{rand_core::UnwrapErr, SysRng};
use lms_signature::lms::{
    LmsMode, LmsSha256M32H10, LmsSha256M32H5, Signature as RawSignature,
    SigningKey as RawSigningKey, VerifyingKey as RawVerifyingKey,
};
use lms_signature::ots::{LmsOtsMode, LmsOtsSha256N32W4};
use signature::{RandomizedSignerMut, Verifier};
use std::alloc::{GlobalAlloc, Layout};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const DEFAULT_PARAM_SET_NAME: &str =
    "LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4";

const LMS_PUBLIC_KEY_BYTES: usize = 56;
const LMS_SECRET_KEY_BYTES: usize = 60;

type ModeH5W4 = LmsSha256M32H5<LmsOtsSha256N32W4>;
type ModeH10W4 = LmsSha256M32H10<LmsOtsSha256N32W4>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LmsParamSet {
    H5W4,
    H10W4,
}

impl LmsParamSet {
    pub const fn name(self) -> &'static str {
        match self {
            Self::H5W4 => "LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4",
            Self::H10W4 => "LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4",
        }
    }

    pub const fn tree_height(self) -> usize {
        match self {
            Self::H5W4 => 5,
            Self::H10W4 => 10,
        }
    }

    pub const fn max_signatures(self) -> u32 {
        match self {
            Self::H5W4 => <ModeH5W4 as LmsMode>::LEAVES,
            Self::H10W4 => <ModeH10W4 as LmsMode>::LEAVES,
        }
    }

    pub const fn signature_size_bytes(self) -> usize {
        8 + LmsOtsSha256N32W4::SIG_LEN + 32 * self.tree_height()
    }
}

pub const LMS_PARAM_SETS: [LmsParamSet; 2] =
    [LmsParamSet::H5W4, LmsParamSet::H10W4];

pub fn param_set_by_name(name: &str) -> Option<LmsParamSet> {
    LMS_PARAM_SETS
        .iter()
        .copied()
        .find(|param_set| param_set.name() == name)
}

pub enum LmsPublicKey {
    H5W4(RawVerifyingKey<ModeH5W4>),
    H10W4(RawVerifyingKey<ModeH10W4>),
}

impl LmsPublicKey {
    pub fn param_set(&self) -> LmsParamSet {
        match self {
            Self::H5W4(_) => LmsParamSet::H5W4,
            Self::H10W4(_) => LmsParamSet::H10W4,
        }
    }
}

pub enum LmsSecretKey {
    H5W4(RawSigningKey<ModeH5W4>),
    H10W4(RawSigningKey<ModeH10W4>),
}

impl LmsSecretKey {
    pub fn param_set(&self) -> LmsParamSet {
        match self {
            Self::H5W4(_) => LmsParamSet::H5W4,
            Self::H10W4(_) => LmsParamSet::H10W4,
        }
    }

    pub fn q(&self) -> u32 {
        match self {
            Self::H5W4(secret_key) => secret_key.q(),
            Self::H10W4(secret_key) => secret_key.q(),
        }
    }
}

pub enum LmsSignature {
    H5W4(RawSignature<ModeH5W4>),
    H10W4(RawSignature<ModeH10W4>),
}

impl LmsSignature {
    pub fn param_set(&self) -> LmsParamSet {
        match self {
            Self::H5W4(_) => LmsParamSet::H5W4,
            Self::H10W4(_) => LmsParamSet::H10W4,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LmsSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LmsScheme {
    params: LmsParamSet,
}

impl LmsScheme {
    pub fn new(params: LmsParamSet) -> Self {
        Self { params }
    }

    pub fn from_param_set_name(name: &str) -> Result<Self, LmsError> {
        let params = param_set_by_name(name).ok_or_else(|| {
            LmsError::UnknownParamSet {
                name: name.to_owned(),
            }
        })?;
        Ok(Self::new(params))
    }

    pub fn algorithm_name(&self) -> &'static str {
        "LMS"
    }

    pub fn backend_name(&self) -> &'static str {
        "lms-signature"
    }

    pub fn param_set_name(&self) -> &'static str {
        self.params.name()
    }

    pub fn tree_height(&self) -> usize {
        self.params.tree_height()
    }

    pub fn max_signatures_per_key(&self) -> u32 {
        self.params.max_signatures()
    }

    pub fn sizes(&self) -> LmsSizes {
        LmsSizes {
            public_key_bytes: LMS_PUBLIC_KEY_BYTES,
            secret_key_bytes: LMS_SECRET_KEY_BYTES,
            signature_bytes: self.params.signature_size_bytes(),
        }
    }

    pub fn keypair(&self) -> Result<(LmsPublicKey, LmsSecretKey), LmsError> {
        let seed = default_seed();
        self.keypair_with_seed(seed)
    }

    pub fn keypair_with_seed(
        &self,
        seed_value: u64,
    ) -> Result<(LmsPublicKey, LmsSecretKey), LmsError> {
        let (id, seed) = seed_material_from_u64(seed_value);

        match self.params {
            LmsParamSet::H5W4 => {
                let secret_key =
                    RawSigningKey::<ModeH5W4>::new_from_seed(id, seed)
                        .map_err(|_| LmsError::KeygenFailed)?;
                let public_key = secret_key.public();
                Ok((
                    LmsPublicKey::H5W4(public_key),
                    LmsSecretKey::H5W4(secret_key),
                ))
            }
            LmsParamSet::H10W4 => {
                let secret_key =
                    RawSigningKey::<ModeH10W4>::new_from_seed(id, seed)
                        .map_err(|_| LmsError::KeygenFailed)?;
                let public_key = secret_key.public();
                Ok((
                    LmsPublicKey::H10W4(public_key),
                    LmsSecretKey::H10W4(secret_key),
                ))
            }
        }
    }

    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &mut LmsSecretKey,
    ) -> Result<LmsSignature, LmsError> {
        self.ensure_secret_key_params(secret_key)?;

        match secret_key {
            LmsSecretKey::H5W4(secret_key) => {
                let mut rng = UnwrapErr(SysRng);
                let signature = secret_key
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| LmsError::SignFailed)?;
                Ok(LmsSignature::H5W4(signature))
            }
            LmsSecretKey::H10W4(secret_key) => {
                let mut rng = UnwrapErr(SysRng);
                let signature = secret_key
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| LmsError::SignFailed)?;
                Ok(LmsSignature::H10W4(signature))
            }
        }
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &LmsSignature,
        public_key: &LmsPublicKey,
    ) -> Result<bool, LmsError> {
        self.ensure_public_key_params(public_key)?;
        self.ensure_signature_params(signature)?;

        match (signature, public_key) {
            (LmsSignature::H5W4(signature), LmsPublicKey::H5W4(public_key)) => {
                Ok(public_key.verify(message, signature).is_ok())
            }
            (
                LmsSignature::H10W4(signature),
                LmsPublicKey::H10W4(public_key),
            ) => Ok(public_key.verify(message, signature).is_ok()),
            _ => Err(LmsError::VerifyFailed),
        }
    }

    pub fn public_key_size(&self, public_key: &LmsPublicKey) -> usize {
        let _ = public_key;
        LMS_PUBLIC_KEY_BYTES
    }

    pub fn secret_key_size(&self, secret_key: &LmsSecretKey) -> usize {
        let _ = secret_key;
        LMS_SECRET_KEY_BYTES
    }

    pub fn signature_size(&self, signature: &LmsSignature) -> usize {
        signature.param_set().signature_size_bytes()
    }

    pub fn remaining_signatures(
        &self,
        secret_key: &LmsSecretKey,
    ) -> Result<u32, LmsError> {
        self.ensure_secret_key_params(secret_key)?;
        Ok(self.max_signatures_per_key().saturating_sub(secret_key.q()))
    }

    fn ensure_secret_key_params(
        &self,
        secret_key: &LmsSecretKey,
    ) -> Result<(), LmsError> {
        if secret_key.param_set() != self.params {
            return Err(LmsError::ParamSetMismatch {
                expected: self.params.name(),
                actual: secret_key.param_set().name(),
            });
        }
        Ok(())
    }

    fn ensure_public_key_params(
        &self,
        public_key: &LmsPublicKey,
    ) -> Result<(), LmsError> {
        if public_key.param_set() != self.params {
            return Err(LmsError::ParamSetMismatch {
                expected: self.params.name(),
                actual: public_key.param_set().name(),
            });
        }
        Ok(())
    }

    fn ensure_signature_params(
        &self,
        signature: &LmsSignature,
    ) -> Result<(), LmsError> {
        if signature.param_set() != self.params {
            return Err(LmsError::ParamSetMismatch {
                expected: self.params.name(),
                actual: signature.param_set().name(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmsError {
    UnknownParamSet {
        name: String,
    },
    ParamSetMismatch {
        expected: &'static str,
        actual: &'static str,
    },
    KeygenFailed,
    SignFailed,
    VerifyFailed,
}

impl fmt::Display for LmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParamSet { name } => {
                write!(f, "unknown LMS param set: {name}")
            }
            Self::ParamSetMismatch { expected, actual } => {
                write!(
                    f,
                    "parameter set mismatch: expected {expected}, got {actual}"
                )
            }
            Self::KeygenFailed => write!(f, "LMS key generation failed"),
            Self::SignFailed => write!(f, "LMS signing failed"),
            Self::VerifyFailed => write!(f, "LMS verification failed"),
        }
    }
}

impl Error for LmsError {}

pub fn bench_message(size: usize) -> Vec<u8> {
    vec![BENCH_MESSAGE_BYTE; size]
}

pub fn signed_message_size(message_len: usize, signature_len: usize) -> usize {
    message_len.saturating_add(signature_len)
}

pub fn measure_time<T, F>(operation: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

pub fn default_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id() as u64;
    now.as_nanos() as u64 ^ (pid << 32)
}

fn seed_material_from_u64(seed_value: u64) -> ([u8; 16], [u8; 32]) {
    let mut rng = XorShift64::new(seed_value);
    let mut out = [0u8; 48];

    let mut offset = 0;
    while offset < out.len() {
        let chunk = rng.next_u64().to_le_bytes();
        let take = (out.len() - offset).min(chunk.len());
        out[offset..offset + take].copy_from_slice(&chunk[..take]);
        offset += take;
    }

    let mut id = [0u8; 16];
    id.copy_from_slice(&out[..16]);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[16..48]);

    (id, seed)
}

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
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
        bench_message, param_set_by_name, LmsScheme, BENCH_MESSAGE_BYTE,
        DEFAULT_PARAM_SET_NAME,
    };

    #[test]
    fn param_set_lookup_works() {
        let found = param_set_by_name(DEFAULT_PARAM_SET_NAME)
            .expect("known param set should resolve");
        assert_eq!(found.name(), DEFAULT_PARAM_SET_NAME);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let scheme = LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .expect("param set should resolve");
        let message = b"lms-roundtrip";
        let (public_key, mut secret_key) =
            scheme.keypair_with_seed(7).expect("keypair should succeed");

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
        let scheme = LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .expect("param set should resolve");
        let (public_key, mut secret_key) = scheme
            .keypair_with_seed(11)
            .expect("keypair should succeed");

        let signature = scheme
            .sign(b"message-a", &mut secret_key)
            .expect("sign should succeed");
        let verified = scheme
            .verify(b"message-b", &signature, &public_key)
            .expect("verify should succeed");
        assert!(!verified, "different message should fail verification");
    }

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let msg = bench_message(16);
        assert_eq!(msg.len(), 16);
        assert!(msg.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }
}
