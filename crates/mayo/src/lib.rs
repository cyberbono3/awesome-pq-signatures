use pq_mayo::{KeyPair, Mayo1, Signature as RawMayoSignature};
use signature::{Error as SignatureError, Signer, Verifier};
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;

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

pub trait SignatureScheme {
    type Seed;
    type KeyPair;
    type Signature;
    type Error;

    fn algorithm_name(&self) -> &'static str;
    fn keypair(&self, seed: &Self::Seed) -> Self::KeyPair;
    fn sign(
        &self,
        keypair: &Self::KeyPair,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature, Self::Error>;
    fn verify(
        &self,
        keypair: &Self::KeyPair,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> bool;
    fn public_key_size(&self, keypair: &Self::KeyPair) -> usize;
    fn secret_key_size(&self, keypair: &Self::KeyPair) -> usize;
    fn signature_size(&self, signature: &Self::Signature) -> usize;
}

pub type MayoSeed = [u8; 24];
pub type MayoKeyPair = KeyPair<Mayo1>;
pub type MayoSignature = RawMayoSignature<Mayo1>;

#[derive(Debug)]
pub enum MayoError {
    UnsupportedContext,
    Crypto(SignatureError),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MayoScheme;

pub const MAYO: MayoScheme = MayoScheme;

impl SignatureScheme for MayoScheme {
    type Seed = MayoSeed;
    type KeyPair = MayoKeyPair;
    type Signature = MayoSignature;
    type Error = MayoError;

    fn algorithm_name(&self) -> &'static str {
        "MAYO"
    }

    fn keypair(&self, seed: &Self::Seed) -> Self::KeyPair {
        MayoKeyPair::from_seed(seed)
            .expect("MAYO key generation from seed should succeed")
    }

    fn sign(
        &self,
        keypair: &Self::KeyPair,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        if !context.is_empty() {
            return Err(MayoError::UnsupportedContext);
        }

        keypair
            .signing_key()
            .try_sign(message)
            .map_err(MayoError::Crypto)
    }

    fn verify(
        &self,
        keypair: &Self::KeyPair,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        if !context.is_empty() {
            return false;
        }

        keypair.verifying_key().verify(message, signature).is_ok()
    }

    fn public_key_size(&self, keypair: &Self::KeyPair) -> usize {
        keypair.verifying_key().as_ref().len()
    }

    fn secret_key_size(&self, keypair: &Self::KeyPair) -> usize {
        keypair.signing_key().as_ref().len()
    }

    fn signature_size(&self, signature: &Self::Signature) -> usize {
        signature.as_ref().len()
    }
}

pub fn default_seed() -> MayoSeed {
    [7_u8; 24]
}

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

#[cfg(test)]
mod tests {
    use super::{
        bench_message, default_seed, signed_message_size, SignatureScheme,
        BENCH_MESSAGE_BYTE, MAYO,
    };

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
    fn mayo_sign_verify_roundtrip() {
        let scheme = MAYO;
        let seed = default_seed();
        let message = b"mayo";
        let context: &[u8] = &[];

        let keypair = scheme.keypair(&seed);
        let signature = scheme
            .sign(&keypair, message, context)
            .expect("signing should succeed");
        let verified = scheme.verify(&keypair, message, context, &signature);
        assert!(verified, "signature verification should succeed");
    }
}
