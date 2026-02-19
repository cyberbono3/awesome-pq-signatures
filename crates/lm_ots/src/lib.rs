use getrandom::SysRng;
use lms_signature::ots::{
    self, LmsOtsMode, LmsOtsSha256N32W1, LmsOtsSha256N32W2, LmsOtsSha256N32W4,
    LmsOtsSha256N32W8,
};
use rand_core::{CryptoRng, TryCryptoRng, TryRng, UnwrapErr};
use signature::{RandomizedSignerMut, Verifier};
use std::alloc::{GlobalAlloc, Layout};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const LMOTS_Q: u32 = 0;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LmOtsParamSet {
    Sha256N32W1,
    Sha256N32W2,
    Sha256N32W4,
    Sha256N32W8,
}

impl LmOtsParamSet {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256N32W1 => "LMOTS_SHA256_N32_W1",
            Self::Sha256N32W2 => "LMOTS_SHA256_N32_W2",
            Self::Sha256N32W4 => "LMOTS_SHA256_N32_W4",
            Self::Sha256N32W8 => "LMOTS_SHA256_N32_W8",
        }
    }
}

impl Default for LmOtsParamSet {
    fn default() -> Self {
        Self::Sha256N32W4
    }
}

impl fmt::Display for LmOtsParamSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for LmOtsParamSet {
    type Err = LmOtsParseParamSetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_uppercase().replace('-', "_");
        match normalized.as_str() {
            "LMOTS_SHA256_N32_W1" | "SHA256_N32_W1" | "W1" => {
                Ok(Self::Sha256N32W1)
            }
            "LMOTS_SHA256_N32_W2" | "SHA256_N32_W2" | "W2" => {
                Ok(Self::Sha256N32W2)
            }
            "LMOTS_SHA256_N32_W4" | "SHA256_N32_W4" | "W4" => {
                Ok(Self::Sha256N32W4)
            }
            "LMOTS_SHA256_N32_W8" | "SHA256_N32_W8" | "W8" => {
                Ok(Self::Sha256N32W8)
            }
            _ => Err(LmOtsParseParamSetError(value.to_owned())),
        }
    }
}

#[derive(Debug)]
pub struct LmOtsParseParamSetError(String);

impl fmt::Display for LmOtsParseParamSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown LM-OTS parameter set: {}; expected one of: \
LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8",
            self.0
        )
    }
}

impl Error for LmOtsParseParamSetError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct LmOtsSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Debug)]
pub enum LmOtsError {
    ParamSetMismatch,
    Sign(signature::Error),
}

impl fmt::Display for LmOtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParamSetMismatch => {
                write!(
                    f,
                    "LM-OTS key/signature does not match selected param set"
                )
            }
            Self::Sign(err) => write!(f, "LM-OTS signing failed: {err}"),
        }
    }
}

impl Error for LmOtsError {}

impl From<signature::Error> for LmOtsError {
    fn from(value: signature::Error) -> Self {
        Self::Sign(value)
    }
}

pub enum LmOtsVerifyingKey {
    Sha256N32W1(ots::VerifyingKey<LmsOtsSha256N32W1>),
    Sha256N32W2(ots::VerifyingKey<LmsOtsSha256N32W2>),
    Sha256N32W4(ots::VerifyingKey<LmsOtsSha256N32W4>),
    Sha256N32W8(ots::VerifyingKey<LmsOtsSha256N32W8>),
}

pub enum LmOtsSigningKey {
    Sha256N32W1(ots::SigningKey<LmsOtsSha256N32W1>),
    Sha256N32W2(ots::SigningKey<LmsOtsSha256N32W2>),
    Sha256N32W4(ots::SigningKey<LmsOtsSha256N32W4>),
    Sha256N32W8(ots::SigningKey<LmsOtsSha256N32W8>),
}

pub enum LmOtsSignature {
    Sha256N32W1(ots::Signature<LmsOtsSha256N32W1>),
    Sha256N32W2(ots::Signature<LmsOtsSha256N32W2>),
    Sha256N32W4(ots::Signature<LmsOtsSha256N32W4>),
    Sha256N32W8(ots::Signature<LmsOtsSha256N32W8>),
}

#[derive(Clone, Copy, Debug)]
pub struct LmOtsScheme {
    param_set: LmOtsParamSet,
}

impl LmOtsScheme {
    pub const fn new(param_set: LmOtsParamSet) -> Self {
        Self { param_set }
    }

    pub const fn algorithm_name(&self) -> &'static str {
        "LM-OTS"
    }

    pub const fn backend_name(&self) -> &'static str {
        "lms-signature-0.1.0-rc.2"
    }

    pub const fn param_set(&self) -> LmOtsParamSet {
        self.param_set
    }

    pub const fn max_signatures_per_key(&self) -> usize {
        1
    }

    pub fn param_set_name(&self) -> &'static str {
        self.param_set.as_str()
    }

    pub fn sizes(&self) -> LmOtsSizes {
        match self.param_set {
            LmOtsParamSet::Sha256N32W1 => sizes_for_mode::<LmsOtsSha256N32W1>(),
            LmOtsParamSet::Sha256N32W2 => sizes_for_mode::<LmsOtsSha256N32W2>(),
            LmOtsParamSet::Sha256N32W4 => sizes_for_mode::<LmsOtsSha256N32W4>(),
            LmOtsParamSet::Sha256N32W8 => sizes_for_mode::<LmsOtsSha256N32W8>(),
        }
    }

    pub fn keypair(
        &self,
        q: u32,
        id: [u8; 16],
    ) -> (LmOtsVerifyingKey, LmOtsSigningKey) {
        let mut rng = UnwrapErr(SysRng);
        self.keypair_with_rng(q, id, &mut rng)
    }

    pub fn keypair_with_rng<R: CryptoRng>(
        &self,
        q: u32,
        id: [u8; 16],
        rng: &mut R,
    ) -> (LmOtsVerifyingKey, LmOtsSigningKey) {
        match self.param_set {
            LmOtsParamSet::Sha256N32W1 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W1>::new(q, id, rng);
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W1(pk),
                    LmOtsSigningKey::Sha256N32W1(sk),
                )
            }
            LmOtsParamSet::Sha256N32W2 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W2>::new(q, id, rng);
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W2(pk),
                    LmOtsSigningKey::Sha256N32W2(sk),
                )
            }
            LmOtsParamSet::Sha256N32W4 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W4>::new(q, id, rng);
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W4(pk),
                    LmOtsSigningKey::Sha256N32W4(sk),
                )
            }
            LmOtsParamSet::Sha256N32W8 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W8>::new(q, id, rng);
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W8(pk),
                    LmOtsSigningKey::Sha256N32W8(sk),
                )
            }
        }
    }

    pub fn keypair_with_seed(
        &self,
        q: u32,
        id: [u8; 16],
        seed: [u8; 32],
    ) -> (LmOtsVerifyingKey, LmOtsSigningKey) {
        match self.param_set {
            LmOtsParamSet::Sha256N32W1 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W1>::new_from_seed(
                    q, id, seed,
                );
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W1(pk),
                    LmOtsSigningKey::Sha256N32W1(sk),
                )
            }
            LmOtsParamSet::Sha256N32W2 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W2>::new_from_seed(
                    q, id, seed,
                );
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W2(pk),
                    LmOtsSigningKey::Sha256N32W2(sk),
                )
            }
            LmOtsParamSet::Sha256N32W4 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W4>::new_from_seed(
                    q, id, seed,
                );
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W4(pk),
                    LmOtsSigningKey::Sha256N32W4(sk),
                )
            }
            LmOtsParamSet::Sha256N32W8 => {
                let sk = ots::SigningKey::<LmsOtsSha256N32W8>::new_from_seed(
                    q, id, seed,
                );
                let pk = sk.public();
                (
                    LmOtsVerifyingKey::Sha256N32W8(pk),
                    LmOtsSigningKey::Sha256N32W8(sk),
                )
            }
        }
    }

    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &mut LmOtsSigningKey,
    ) -> Result<LmOtsSignature, LmOtsError> {
        let mut rng = SysRng;
        self.sign_with_rng(message, secret_key, &mut rng)
    }

    pub fn sign_with_seed(
        &self,
        message: &[u8],
        secret_key: &mut LmOtsSigningKey,
        seed: u64,
    ) -> Result<LmOtsSignature, LmOtsError> {
        let mut rng = XorShift64TryRng::new(seed);
        self.sign_with_rng(message, secret_key, &mut rng)
    }

    pub fn sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        secret_key: &mut LmOtsSigningKey,
        rng: &mut R,
    ) -> Result<LmOtsSignature, LmOtsError> {
        match (self.param_set, secret_key) {
            (LmOtsParamSet::Sha256N32W1, LmOtsSigningKey::Sha256N32W1(sk)) => {
                sk.try_sign_with_rng(rng, message)
                    .map(LmOtsSignature::Sha256N32W1)
                    .map_err(LmOtsError::from)
            }
            (LmOtsParamSet::Sha256N32W2, LmOtsSigningKey::Sha256N32W2(sk)) => {
                sk.try_sign_with_rng(rng, message)
                    .map(LmOtsSignature::Sha256N32W2)
                    .map_err(LmOtsError::from)
            }
            (LmOtsParamSet::Sha256N32W4, LmOtsSigningKey::Sha256N32W4(sk)) => {
                sk.try_sign_with_rng(rng, message)
                    .map(LmOtsSignature::Sha256N32W4)
                    .map_err(LmOtsError::from)
            }
            (LmOtsParamSet::Sha256N32W8, LmOtsSigningKey::Sha256N32W8(sk)) => {
                sk.try_sign_with_rng(rng, message)
                    .map(LmOtsSignature::Sha256N32W8)
                    .map_err(LmOtsError::from)
            }
            _ => Err(LmOtsError::ParamSetMismatch),
        }
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &LmOtsSignature,
        public_key: &LmOtsVerifyingKey,
    ) -> Result<bool, LmOtsError> {
        match (self.param_set, public_key, signature) {
            (
                LmOtsParamSet::Sha256N32W1,
                LmOtsVerifyingKey::Sha256N32W1(pk),
                LmOtsSignature::Sha256N32W1(sig),
            ) => Ok(pk.verify(message, sig).is_ok()),
            (
                LmOtsParamSet::Sha256N32W2,
                LmOtsVerifyingKey::Sha256N32W2(pk),
                LmOtsSignature::Sha256N32W2(sig),
            ) => Ok(pk.verify(message, sig).is_ok()),
            (
                LmOtsParamSet::Sha256N32W4,
                LmOtsVerifyingKey::Sha256N32W4(pk),
                LmOtsSignature::Sha256N32W4(sig),
            ) => Ok(pk.verify(message, sig).is_ok()),
            (
                LmOtsParamSet::Sha256N32W8,
                LmOtsVerifyingKey::Sha256N32W8(pk),
                LmOtsSignature::Sha256N32W8(sig),
            ) => Ok(pk.verify(message, sig).is_ok()),
            _ => Err(LmOtsError::ParamSetMismatch),
        }
    }
}

impl Default for LmOtsScheme {
    fn default() -> Self {
        Self::new(LmOtsParamSet::default())
    }
}

pub const LM_OTS_SHA256_N32_W4: LmOtsScheme =
    LmOtsScheme::new(LmOtsParamSet::Sha256N32W4);

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

pub fn default_identifier() -> [u8; 16] {
    identifier_from_seed(seed_from_str("lm-ots-default-id"))
}

pub fn identifier_from_seed(seed: u64) -> [u8; 16] {
    let mut rng = XorShift64TryRng::new(seed);
    let mut out = [0_u8; 16];
    rng.fill_bytes_infallible(&mut out);
    out
}

pub fn seed_bytes_from_u64(seed: u64) -> [u8; 32] {
    let mut rng = XorShift64TryRng::new(seed);
    let mut out = [0_u8; 32];
    rng.fill_bytes_infallible(&mut out);
    out
}

pub fn random_seed(label: &str) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id() as u64;
    (now.as_nanos() as u64) ^ (pid << 32) ^ seed_from_str(label)
}

pub fn seed_from_str(seed: &str) -> u64 {
    // FNV-1a 64-bit
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in seed.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Clone, Copy, Debug)]
pub struct XorShift64TryRng {
    state: u64,
}

impl XorShift64TryRng {
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

    fn fill_bytes_infallible(&mut self, out: &mut [u8]) {
        let mut offset = 0;
        while offset < out.len() {
            let chunk = self.next_u64().to_le_bytes();
            let take = (out.len() - offset).min(chunk.len());
            out[offset..offset + take].copy_from_slice(&chunk[..take]);
            offset += take;
        }
    }
}

impl TryRng for XorShift64TryRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_u64() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_bytes_infallible(dest);
        Ok(())
    }
}

impl TryCryptoRng for XorShift64TryRng {}

fn sizes_for_mode<Mode: LmsOtsMode>() -> LmOtsSizes {
    LmOtsSizes {
        public_key_bytes: 4 + 16 + 4 + Mode::N,
        secret_key_bytes: 4 + 16 + (Mode::N * Mode::P) + 1,
        signature_bytes: Mode::SIG_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::{default_identifier, seed_bytes_from_u64, seed_from_str};
    use super::{LmOtsParamSet, LmOtsScheme, LMOTS_Q};
    use std::str::FromStr;

    #[test]
    fn parse_param_set() {
        assert_eq!(
            LmOtsParamSet::from_str("LMOTS_SHA256_N32_W4").expect("parse"),
            LmOtsParamSet::Sha256N32W4
        );
        assert_eq!(
            LmOtsParamSet::from_str("w8").expect("parse"),
            LmOtsParamSet::Sha256N32W8
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let scheme = LmOtsScheme::new(LmOtsParamSet::Sha256N32W4);
        let id = default_identifier();
        let seed = seed_bytes_from_u64(seed_from_str("roundtrip-key"));
        let (public_key, mut secret_key) =
            scheme.keypair_with_seed(LMOTS_Q, id, seed);

        let signature = scheme
            .sign_with_seed(
                b"lm-ots roundtrip",
                &mut secret_key,
                seed_from_str("roundtrip-sign"),
            )
            .expect("sign should succeed");

        let valid = scheme
            .verify(b"lm-ots roundtrip", &signature, &public_key)
            .expect("verify should succeed");
        assert!(valid, "signature should verify");
    }

    #[test]
    fn key_reuse_is_rejected() {
        let scheme = LmOtsScheme::new(LmOtsParamSet::Sha256N32W4);
        let id = default_identifier();
        let seed = seed_bytes_from_u64(seed_from_str("reuse-key"));
        let (_public_key, mut secret_key) =
            scheme.keypair_with_seed(LMOTS_Q, id, seed);

        let first = scheme.sign_with_seed(
            b"first",
            &mut secret_key,
            seed_from_str("reuse-sign-1"),
        );
        assert!(first.is_ok(), "first sign should succeed");

        let second = scheme.sign_with_seed(
            b"second",
            &mut secret_key,
            seed_from_str("reuse-sign-2"),
        );
        assert!(second.is_err(), "second sign should fail");
    }

    #[test]
    fn verify_rejects_other_message() {
        let scheme = LmOtsScheme::new(LmOtsParamSet::Sha256N32W4);
        let id = default_identifier();
        let seed = seed_bytes_from_u64(seed_from_str("verify-msg-key"));
        let (public_key, mut secret_key) =
            scheme.keypair_with_seed(LMOTS_Q, id, seed);
        let signature = scheme
            .sign_with_seed(
                b"message-a",
                &mut secret_key,
                seed_from_str("verify-msg-sign"),
            )
            .expect("sign should succeed");

        let valid = scheme
            .verify(b"message-b", &signature, &public_key)
            .expect("verify should succeed");
        assert!(!valid, "different message should not verify");
    }
}
