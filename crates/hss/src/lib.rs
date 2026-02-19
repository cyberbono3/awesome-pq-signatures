use hbs_lms::signature::{SignerMut, Verifier};
use hbs_lms::{
    keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256,
    Signature, SigningKey, VerifyingKey,
};
use std::alloc::{GlobalAlloc, Layout};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const DEFAULT_PARAM_SET_NAME: &str = "HSS-SHA256-H5-W2-L1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HssParamSet {
    L1H5W2,
    L2H5W2,
}

impl HssParamSet {
    pub const fn name(self) -> &'static str {
        match self {
            Self::L1H5W2 => "HSS-SHA256-H5-W2-L1",
            Self::L2H5W2 => "HSS-SHA256-H5-W2-L2",
        }
    }

    pub const fn levels(self) -> usize {
        match self {
            Self::L1H5W2 => 1,
            Self::L2H5W2 => 2,
        }
    }
}

pub const HSS_PARAM_SETS: [HssParamSet; 2] =
    [HssParamSet::L1H5W2, HssParamSet::L2H5W2];

pub fn param_set_by_name(name: &str) -> Option<HssParamSet> {
    HSS_PARAM_SETS
        .iter()
        .copied()
        .find(|param_set| param_set.name() == name)
}

#[derive(Clone, Debug)]
pub struct HssPublicKey {
    inner: VerifyingKey<Sha256_256>,
    params: HssParamSet,
}

impl HssPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    pub fn byte_len(&self) -> usize {
        self.inner.as_slice().len()
    }
}

#[derive(Clone, Debug)]
pub struct HssSecretKey {
    inner: SigningKey<Sha256_256>,
    params: HssParamSet,
}

impl HssSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    pub fn byte_len(&self) -> usize {
        self.inner.as_slice().len()
    }

    pub fn lifetime(&self) -> Result<u64, HssError> {
        self.inner
            .get_lifetime()
            .map_err(|_| HssError::LifetimeComputationFailed)
    }
}

#[derive(Debug)]
pub struct HssSignature {
    inner: Signature,
    params: HssParamSet,
}

impl HssSignature {
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }

    pub fn byte_len(&self) -> usize {
        self.inner.as_ref().len()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HssSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct HssScheme {
    params: HssParamSet,
}

impl HssScheme {
    pub fn new(params: HssParamSet) -> Self {
        Self { params }
    }

    pub fn from_param_set_name(name: &str) -> Result<Self, HssError> {
        let params = param_set_by_name(name).ok_or_else(|| {
            HssError::UnknownParamSet {
                name: name.to_owned(),
            }
        })?;
        Ok(Self::new(params))
    }

    pub fn algorithm_name(&self) -> &'static str {
        "HSS"
    }

    pub fn backend_name(&self) -> &'static str {
        "hbs-lms"
    }

    pub fn param_set_name(&self) -> &'static str {
        self.params.name()
    }

    pub fn levels(&self) -> usize {
        self.params.levels()
    }

    pub fn sizes(&self) -> Result<HssSizes, HssError> {
        let (public_key, mut secret_key) = self.keypair()?;
        let signature = self.sign(&bench_message(32), &mut secret_key)?;
        Ok(HssSizes {
            public_key_bytes: public_key.byte_len(),
            secret_key_bytes: secret_key.byte_len(),
            signature_bytes: signature.byte_len(),
        })
    }

    pub fn keypair(&self) -> Result<(HssPublicKey, HssSecretKey), HssError> {
        let seed = default_seed();
        self.keypair_with_seed(seed)
    }

    pub fn keypair_with_seed(
        &self,
        seed_value: u64,
    ) -> Result<(HssPublicKey, HssSecretKey), HssError> {
        let mut seed = Seed::<Sha256_256>::default();
        fill_seed_from_u64(seed_value, &mut seed);
        let parameters = parameters_for(self.params);
        let (secret_key, public_key) =
            keygen::<Sha256_256>(&parameters, &seed, None)
                .map_err(|_| HssError::KeygenFailed)?;

        Ok((
            HssPublicKey {
                inner: public_key,
                params: self.params,
            },
            HssSecretKey {
                inner: secret_key,
                params: self.params,
            },
        ))
    }

    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &mut HssSecretKey,
    ) -> Result<HssSignature, HssError> {
        self.ensure_secret_key_params(secret_key)?;
        let signature = secret_key
            .inner
            .try_sign(message)
            .map_err(|_| HssError::SignFailed)?;

        Ok(HssSignature {
            inner: signature,
            params: self.params,
        })
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &HssSignature,
        public_key: &HssPublicKey,
    ) -> Result<bool, HssError> {
        self.ensure_public_key_params(public_key)?;
        self.ensure_signature_params(signature)?;
        Ok(public_key.inner.verify(message, &signature.inner).is_ok())
    }

    pub fn public_key_size(&self, public_key: &HssPublicKey) -> usize {
        public_key.byte_len()
    }

    pub fn secret_key_size(&self, secret_key: &HssSecretKey) -> usize {
        secret_key.byte_len()
    }

    pub fn signature_size(&self, signature: &HssSignature) -> usize {
        signature.byte_len()
    }

    fn ensure_secret_key_params(
        &self,
        secret_key: &HssSecretKey,
    ) -> Result<(), HssError> {
        if secret_key.params != self.params {
            return Err(HssError::ParamSetMismatch {
                expected: self.params.name(),
                actual: secret_key.params.name(),
            });
        }
        Ok(())
    }

    fn ensure_public_key_params(
        &self,
        public_key: &HssPublicKey,
    ) -> Result<(), HssError> {
        if public_key.params != self.params {
            return Err(HssError::ParamSetMismatch {
                expected: self.params.name(),
                actual: public_key.params.name(),
            });
        }
        Ok(())
    }

    fn ensure_signature_params(
        &self,
        signature: &HssSignature,
    ) -> Result<(), HssError> {
        if signature.params != self.params {
            return Err(HssError::ParamSetMismatch {
                expected: self.params.name(),
                actual: signature.params.name(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HssError {
    UnknownParamSet {
        name: String,
    },
    ParamSetMismatch {
        expected: &'static str,
        actual: &'static str,
    },
    KeygenFailed,
    SignFailed,
    LifetimeComputationFailed,
}

impl fmt::Display for HssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParamSet { name } => {
                write!(f, "unknown HSS param set: {name}")
            }
            Self::ParamSetMismatch { expected, actual } => {
                write!(
                    f,
                    "parameter set mismatch: expected {expected}, got {actual}"
                )
            }
            Self::KeygenFailed => write!(f, "HSS key generation failed"),
            Self::SignFailed => write!(f, "HSS signing failed"),
            Self::LifetimeComputationFailed => {
                write!(f, "failed to compute HSS key lifetime")
            }
        }
    }
}

impl Error for HssError {}

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

fn fill_seed_from_u64(seed_value: u64, seed: &mut Seed<Sha256_256>) {
    let mut rng = XorShift64::new(seed_value);
    let out = seed.as_mut_slice();

    let mut offset = 0;
    while offset < out.len() {
        let chunk = rng.next_u64().to_le_bytes();
        let take = (out.len() - offset).min(chunk.len());
        out[offset..offset + take].copy_from_slice(&chunk[..take]);
        offset += take;
    }
}

fn parameters_for(param_set: HssParamSet) -> Vec<HssParameter<Sha256_256>> {
    match param_set {
        HssParamSet::L1H5W2 => vec![HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        )],
        HssParamSet::L2H5W2 => vec![
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ],
    }
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
        bench_message, param_set_by_name, HssScheme, BENCH_MESSAGE_BYTE,
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
        std::thread::Builder::new()
            .name("hss-roundtrip".to_owned())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let scheme =
                    HssScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
                        .expect("param set should resolve");
                let message = b"hss-roundtrip";
                let (public_key, mut secret_key) =
                    scheme.keypair().expect("keypair should succeed");

                let signature = scheme
                    .sign(message, &mut secret_key)
                    .expect("sign should succeed");
                let verified = scheme
                    .verify(message, &signature, &public_key)
                    .expect("verify should succeed");
                assert!(verified, "signature should verify");
            })
            .expect("test thread should start")
            .join()
            .expect("test thread should complete");
    }

    #[test]
    fn verify_fails_for_other_message() {
        std::thread::Builder::new()
            .name("hss-verify-fail".to_owned())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let scheme =
                    HssScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
                        .expect("param set should resolve");
                let (public_key, mut secret_key) =
                    scheme.keypair().expect("keypair should succeed");

                let signature = scheme
                    .sign(b"message-a", &mut secret_key)
                    .expect("sign should succeed");
                let verified = scheme
                    .verify(b"message-b", &signature, &public_key)
                    .expect("verify should succeed");
                assert!(
                    !verified,
                    "different message should fail verification"
                );
            })
            .expect("test thread should start")
            .join()
            .expect("test thread should complete");
    }

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let msg = bench_message(16);
        assert_eq!(msg.len(), 16);
        assert!(msg.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }
}
