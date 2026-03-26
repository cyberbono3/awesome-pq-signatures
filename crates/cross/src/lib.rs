use std::alloc::{GlobalAlloc, Layout};
use std::ffi::{c_int, c_uchar, c_ulonglong};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Canonical 32-byte message (SHA-256 digest) that every DSA crate signs.
pub use pq_bench::BENCH_MESSAGE;

include!(concat!(env!("OUT_DIR"), "/cross_variant.rs"));

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;

const CROSS_SEED_BYTES: usize = 16;
const KEYGEN_PROFILE: DeterministicRngProfile = DeterministicRngProfile {
    seed: *b"cross-keygenseed",
    domain_separator: 0,
};
const SIGN_PROFILE: DeterministicRngProfile = DeterministicRngProfile {
    seed: *b"cross-signing-se",
    domain_separator: 1,
};

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static CROSS_FFI_LOCK: Mutex<()> = Mutex::new(());

pub struct TrackingAllocator<A: GlobalAlloc + Sync + 'static> {
    inner: &'static A,
}

impl<A: GlobalAlloc + Sync + 'static> TrackingAllocator<A> {
    pub const fn new(inner: &'static A) -> Self {
        Self { inner }
    }
}

unsafe impl<A: GlobalAlloc + Sync + 'static> GlobalAlloc for TrackingAllocator<A> {
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

type CrossSeed = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeterministicRngProfile {
    seed: CrossSeed,
    domain_separator: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CrossDimensions {
    public_key: usize,
    secret_key: usize,
    signature: usize,
}

struct NativeCross;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl CrossKeyPair {
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    #[must_use]
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossSignature(Vec<u8>);

impl CrossSignature {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossError {
    FfiLockPoisoned,
    KeygenFailed(i32),
    SignFailed(i32),
    VerifyFailed(i32),
    InvalidSignedMessage,
    LengthOverflow,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CrossScheme;

pub const CROSS: CrossScheme = CrossScheme;

impl CrossScheme {
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        CROSS_VARIANT
    }

    /// # Errors
    ///
    /// Returns an error if the native CROSS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn keypair(&self) -> Result<CrossKeyPair, CrossError> {
        self.keypair_with_seed(KEYGEN_PROFILE.seed)
    }

    /// # Errors
    ///
    /// Returns an error if the native CROSS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn benchmark_keypair(&self) -> Result<CrossKeyPair, CrossError> {
        self.keypair()
    }

    /// # Errors
    ///
    /// Returns an error if the native CROSS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn keypair_with_seed(&self, seed: CrossSeed) -> Result<CrossKeyPair, CrossError> {
        let profile = DeterministicRngProfile {
            seed,
            domain_separator: KEYGEN_PROFILE.domain_separator,
        };
        NativeCross::with_rng(profile, |_| NativeCross::keypair())
    }

    /// # Errors
    ///
    /// Returns an error if signing fails, the message length exceeds the native
    /// API width, or if the native runtime lock is poisoned.
    pub fn sign(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
    ) -> Result<CrossSignature, CrossError> {
        NativeCross::with_rng(SIGN_PROFILE, |_| NativeCross::sign(keypair, message))
    }

    /// # Errors
    ///
    /// Returns an error if signing fails, the message length exceeds the native
    /// API width, or if the native runtime lock is poisoned.
    pub fn sign_message(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
    ) -> Result<CrossSignature, CrossError> {
        self.sign(keypair, message)
    }

    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly, the message length
    /// exceeds the native API width, or if the native runtime lock is poisoned.
    pub fn verify(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
        signature: &CrossSignature,
    ) -> Result<bool, CrossError> {
        NativeCross::verify(keypair, message, signature)
    }

    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly, the message length
    /// exceeds the native API width, or if the native runtime lock is poisoned.
    pub fn verify_message(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
        signature: &CrossSignature,
    ) -> Result<bool, CrossError> {
        self.verify(keypair, message, signature)
    }

    #[must_use]
    pub fn public_key_size(&self, _keypair: &CrossKeyPair) -> usize {
        NativeCross::dimensions().public_key
    }

    #[must_use]
    pub fn secret_key_size(&self, _keypair: &CrossKeyPair) -> usize {
        NativeCross::dimensions().secret_key
    }

    #[must_use]
    pub fn signature_size(&self, _signature: &CrossSignature) -> usize {
        NativeCross::dimensions().signature
    }

    #[must_use]
    pub fn sizes(&self, keypair: &CrossKeyPair, signature: &CrossSignature) -> CrossSizes {
        CrossSizes {
            public_key: self.public_key_size(keypair),
            secret_key: self.secret_key_size(keypair),
            signature: self.signature_size(signature),
        }
    }
}

impl NativeCross {
    fn dimensions() -> CrossDimensions {
        CrossDimensions {
            public_key: unsafe { cross_rs_public_key_bytes() },
            secret_key: unsafe { cross_rs_secret_key_bytes() },
            signature: unsafe { cross_rs_signature_bytes() },
        }
    }

    fn with_rng<T, F>(profile: DeterministicRngProfile, operation: F) -> Result<T, CrossError>
    where
        F: FnOnce(&Self) -> Result<T, CrossError>,
    {
        let _guard = CROSS_FFI_LOCK
            .lock()
            .map_err(|_| CrossError::FfiLockPoisoned)?;
        init_rng(&profile);
        operation(&Self)
    }

    fn keypair() -> Result<CrossKeyPair, CrossError> {
        let dimensions = Self::dimensions();
        let mut public_key = vec![0_u8; dimensions.public_key];
        let mut secret_key = vec![0_u8; dimensions.secret_key];
        let rc = unsafe { crypto_sign_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr()) };

        if rc == 0 {
            Ok(CrossKeyPair {
                public_key,
                secret_key,
            })
        } else {
            Err(CrossError::KeygenFailed(rc))
        }
    }

    fn sign(keypair: &CrossKeyPair, message: &[u8]) -> Result<CrossSignature, CrossError> {
        let dimensions = Self::dimensions();
        let message_len = ulonglong_len(message.len())?;
        let mut signed_message =
            vec![0_u8; signed_message_size(message.len(), dimensions.signature)];
        let mut signed_message_len = 0_u64;

        let rc = unsafe {
            crypto_sign(
                signed_message.as_mut_ptr(),
                &raw mut signed_message_len,
                message.as_ptr(),
                message_len,
                keypair.secret_key.as_ptr(),
            )
        };

        if rc != 0 {
            return Err(CrossError::SignFailed(rc));
        }

        let signed_message_len = usize_len(signed_message_len)?;
        extract_signature(message.len(), &signed_message, signed_message_len)
    }

    fn verify(
        keypair: &CrossKeyPair,
        message: &[u8],
        signature: &CrossSignature,
    ) -> Result<bool, CrossError> {
        let _guard = CROSS_FFI_LOCK
            .lock()
            .map_err(|_| CrossError::FfiLockPoisoned)?;

        let signed_message = combine_signed_message(message, signature);
        let signed_message_len = ulonglong_len(signed_message.len())?;
        let mut opened_message = vec![0_u8; message.len()];
        let mut opened_message_len = 0_u64;

        let rc = unsafe {
            crypto_sign_open(
                opened_message.as_mut_ptr(),
                &raw mut opened_message_len,
                signed_message.as_ptr(),
                signed_message_len,
                keypair.public_key.as_ptr(),
            )
        };

        match rc {
            0 => {
                let opened_message_len = usize_len(opened_message_len)?;
                Ok(matches_opened_message(
                    message,
                    &opened_message,
                    opened_message_len,
                ))
            }
            -1 => Ok(false),
            _ => Err(CrossError::VerifyFailed(rc)),
        }
    }
}

#[must_use]
pub fn bench_message(size: usize) -> Vec<u8> {
    vec![BENCH_MESSAGE_BYTE; size]
}

#[must_use]
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

fn init_rng(profile: &DeterministicRngProfile) {
    let seed_len = u32::try_from(CROSS_SEED_BYTES).expect("cross seed length fits in u32");
    unsafe {
        cross_rs_init_rng(profile.seed.as_ptr(), seed_len, profile.domain_separator);
    }
}

fn ulonglong_len(value: usize) -> Result<c_ulonglong, CrossError> {
    c_ulonglong::try_from(value).map_err(|_| CrossError::LengthOverflow)
}

fn usize_len(value: c_ulonglong) -> Result<usize, CrossError> {
    usize::try_from(value).map_err(|_| CrossError::LengthOverflow)
}

fn extract_signature(
    message_len: usize,
    signed_message: &[u8],
    signed_message_len: usize,
) -> Result<CrossSignature, CrossError> {
    signed_message
        .get(message_len..signed_message_len)
        .map(|bytes| CrossSignature(bytes.to_vec()))
        .ok_or(CrossError::InvalidSignedMessage)
}

fn combine_signed_message(message: &[u8], signature: &CrossSignature) -> Vec<u8> {
    let mut signed_message =
        Vec::with_capacity(signed_message_size(message.len(), signature.0.len()));
    signed_message.extend_from_slice(message);
    signed_message.extend_from_slice(signature.as_bytes());
    signed_message
}

fn matches_opened_message(
    expected_message: &[u8],
    opened_message: &[u8],
    opened_message_len: usize,
) -> bool {
    opened_message_len == expected_message.len()
        && opened_message
            .get(..opened_message_len)
            .is_some_and(|message| message == expected_message)
}

unsafe extern "C" {
    fn crypto_sign_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
    fn crypto_sign(
        sm: *mut c_uchar,
        smlen: *mut c_ulonglong,
        m: *const c_uchar,
        mlen: c_ulonglong,
        sk: *const c_uchar,
    ) -> c_int;
    fn crypto_sign_open(
        m: *mut c_uchar,
        mlen: *mut c_ulonglong,
        sm: *const c_uchar,
        smlen: c_ulonglong,
        pk: *const c_uchar,
    ) -> c_int;
    fn cross_rs_init_rng(seed: *const c_uchar, seed_len: u32, dsc: u16);
    fn cross_rs_public_key_bytes() -> usize;
    fn cross_rs_secret_key_bytes() -> usize;
    fn cross_rs_signature_bytes() -> usize;
}

#[cfg(test)]
mod tests {
    use super::{bench_message, signed_message_size, BENCH_MESSAGE_BYTE, CROSS};

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let message = bench_message(16);
        assert_eq!(message.len(), 16);
        assert!(message.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }

    #[test]
    fn signed_message_size_adds_lengths() {
        assert_eq!(signed_message_size(10, 20), 30);
    }

    #[test]
    fn cross_sign_verify_roundtrip() {
        let scheme = CROSS;
        let message = b"cross";

        let keypair = scheme
            .benchmark_keypair()
            .expect("keypair generation should succeed");
        let signature = scheme
            .sign_message(&keypair, message)
            .expect("signing should succeed");
        let verified = scheme
            .verify_message(&keypair, message, &signature)
            .expect("verification should succeed");

        assert!(verified, "signature verification should succeed");

        let sizes = scheme.sizes(&keypair, &signature);
        assert!(sizes.public_key > 0);
        assert!(sizes.secret_key > 0);
        assert!(sizes.signature > 0);
    }
}
