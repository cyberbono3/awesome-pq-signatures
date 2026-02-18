use ml_dsa::{KeyGen, KeyPair, MlDsa65, Signature, B32};
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

#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa65Scheme;

pub const ML_DSA_65: MlDsa65Scheme = MlDsa65Scheme;

impl SignatureScheme for MlDsa65Scheme {
    type Seed = B32;
    type KeyPair = KeyPair<MlDsa65>;
    type Signature = Signature<MlDsa65>;
    type Error = ml_dsa::Error;

    fn algorithm_name(&self) -> &'static str {
        "ML-DSA-65"
    }

    fn keypair(&self, seed: &Self::Seed) -> Self::KeyPair {
        MlDsa65::key_gen_internal(seed)
    }

    fn sign(
        &self,
        keypair: &Self::KeyPair,
        message: &[u8],
        context: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        keypair.signing_key().sign_deterministic(message, context)
    }

    fn verify(
        &self,
        keypair: &Self::KeyPair,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        keypair
            .verifying_key()
            .verify_with_context(message, context, signature)
    }

    fn public_key_size(&self, keypair: &Self::KeyPair) -> usize {
        keypair.verifying_key().encode().len()
    }

    fn secret_key_size(&self, keypair: &Self::KeyPair) -> usize {
        keypair.signing_key().encode().len()
    }

    fn signature_size(&self, signature: &Self::Signature) -> usize {
        signature.encode().len()
    }
}

pub fn default_seed() -> B32 {
    [7_u8; 32].into()
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
        BENCH_MESSAGE_BYTE, ML_DSA_65,
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
    fn ml_dsa_65_sign_verify_roundtrip() {
        let scheme = ML_DSA_65;
        let seed = default_seed();
        let message = b"dilithium";
        let context: &[u8] = &[];

        let keypair = scheme.keypair(&seed);
        let signature = scheme
            .sign(&keypair, message, context)
            .expect("signing should succeed");

        assert!(scheme.verify(&keypair, message, context, &signature));
        assert!(scheme.public_key_size(&keypair) > 0);
        assert!(scheme.secret_key_size(&keypair) > 0);
        assert!(scheme.signature_size(&signature) > 0);
    }
}
