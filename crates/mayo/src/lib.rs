use pq_mayo::{KeyPair, Signature as RawMayoSignature};
use signature::{Error as SignatureError, Signer, Verifier};
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Canonical 32-byte message (SHA-256 digest) that every DSA crate signs.
pub use pq_bench::BENCH_MESSAGE;

include!(concat!(env!("OUT_DIR"), "/mayo_variant.rs"));

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const DEFAULT_CONTEXT: &[u8] = &[];

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

pub type MayoKeyPair = KeyPair<SelectedMayoParam>;
pub type MayoSignature = RawMayoSignature<SelectedMayoParam>;

#[derive(Clone, Copy, Debug, Default)]
pub struct MayoSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Debug)]
pub enum MayoError {
    UnsupportedContext,
    Crypto(SignatureError),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MayoScheme;

pub const MAYO: MayoScheme = MayoScheme;

impl MayoScheme {
    pub fn algorithm_name(&self) -> &'static str {
        MAYO_VARIANT
    }

    pub fn keypair(&self, seed: &MayoSeed) -> MayoKeyPair {
        MayoKeyPair::from_seed(seed).expect("MAYO key generation from seed should succeed")
    }

    pub fn benchmark_keypair(&self) -> MayoKeyPair {
        self.keypair(&default_seed())
    }

    pub fn sign(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
        context: &[u8],
    ) -> Result<MayoSignature, MayoError> {
        self.ensure_context_supported(context)?;

        keypair
            .signing_key()
            .try_sign(message)
            .map_err(MayoError::Crypto)
    }

    pub fn sign_message(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
    ) -> Result<MayoSignature, MayoError> {
        self.sign(keypair, message, DEFAULT_CONTEXT)
    }

    pub fn verify(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
        context: &[u8],
        signature: &MayoSignature,
    ) -> bool {
        if self.ensure_context_supported(context).is_err() {
            return false;
        }

        keypair.verifying_key().verify(message, signature).is_ok()
    }

    pub fn verify_message(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
        signature: &MayoSignature,
    ) -> bool {
        self.verify(keypair, message, DEFAULT_CONTEXT, signature)
    }

    pub fn public_key_size(&self, keypair: &MayoKeyPair) -> usize {
        keypair.verifying_key().as_ref().len()
    }

    pub fn secret_key_size(&self, keypair: &MayoKeyPair) -> usize {
        keypair.signing_key().as_ref().len()
    }

    pub fn signature_size(&self, signature: &MayoSignature) -> usize {
        signature.as_ref().len()
    }

    pub fn sizes(&self, keypair: &MayoKeyPair, signature: &MayoSignature) -> MayoSizes {
        MayoSizes {
            public_key_bytes: self.public_key_size(keypair),
            secret_key_bytes: self.secret_key_size(keypair),
            signature_bytes: self.signature_size(signature),
        }
    }

    fn ensure_context_supported(&self, context: &[u8]) -> Result<(), MayoError> {
        if context.is_empty() {
            Ok(())
        } else {
            Err(MayoError::UnsupportedContext)
        }
    }
}

pub fn default_seed() -> MayoSeed {
    [7_u8; MAYO_SEED_BYTES]
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
    use super::{bench_message, default_seed, signed_message_size, BENCH_MESSAGE_BYTE, MAYO};

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

        let keypair = scheme.keypair(&seed);
        let signature = scheme
            .sign_message(&keypair, message)
            .expect("signing should succeed");
        let verified = scheme.verify_message(&keypair, message, &signature);
        assert!(verified, "signature verification should succeed");
    }
}
