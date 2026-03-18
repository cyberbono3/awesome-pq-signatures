use sqisign_lvl1::{KeyPair, Signature as RawSqisignSignature, SqisignError};
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Canonical 32-byte message (SHA-256 digest) that every DSA crate signs.
pub use pq_config::BENCH_MESSAGE;

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

pub type SqisignKeyPair = KeyPair;
pub type SqisignSignature = RawSqisignSignature;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqisignSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SqisignScheme;

pub const SQISIGN: SqisignScheme = SqisignScheme;

impl SqisignScheme {
    pub fn algorithm_name(&self) -> &'static str {
        "SQISign"
    }

    pub fn keypair(&self) -> Result<SqisignKeyPair, SqisignError> {
        SqisignKeyPair::generate()
    }

    pub fn benchmark_keypair(&self) -> Result<SqisignKeyPair, SqisignError> {
        self.keypair()
    }

    pub fn sign(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
    ) -> Result<SqisignSignature, SqisignError> {
        keypair.sign(message)
    }

    pub fn sign_message(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
    ) -> Result<SqisignSignature, SqisignError> {
        self.sign(keypair, message)
    }

    pub fn verify(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
        signature: &SqisignSignature,
    ) -> Result<bool, SqisignError> {
        keypair.verify(message, signature)
    }

    pub fn verify_message(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
        signature: &SqisignSignature,
    ) -> Result<bool, SqisignError> {
        self.verify(keypair, message, signature)
    }

    pub fn public_key_size(&self, keypair: &SqisignKeyPair) -> usize {
        keypair.public_key.as_bytes().len()
    }

    pub fn secret_key_size(&self, keypair: &SqisignKeyPair) -> usize {
        keypair.secret_key.as_bytes().len()
    }

    pub fn signature_size(&self, signature: &SqisignSignature) -> usize {
        signature.as_bytes().len()
    }

    pub fn sizes(
        &self,
        keypair: &SqisignKeyPair,
        signature: &SqisignSignature,
    ) -> SqisignSizes {
        SqisignSizes {
            public_key: self.public_key_size(keypair),
            secret_key: self.secret_key_size(keypair),
            signature: self.signature_size(signature),
        }
    }
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
        bench_message, signed_message_size, BENCH_MESSAGE_BYTE, SQISIGN,
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
    fn sqisign_sign_verify_roundtrip() {
        let scheme = SQISIGN;
        let message = b"sqisign";

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
