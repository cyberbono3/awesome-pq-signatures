use pqcrypto_sphincsplus::sphincsshake128fsimple;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
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
    type PublicKey: PublicKey;
    type SecretKey: SecretKey;
    type SignedMessage: SignedMessage;

    fn algorithm_name(&self) -> &'static str;
    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey);
    fn sign(
        &self,
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Self::SignedMessage;
    fn open(
        &self,
        signed_message: &Self::SignedMessage,
        public_key: &Self::PublicKey,
    ) -> Option<Vec<u8>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SphincsPlusShake128fSimpleScheme;

pub const SPHINCS_PLUS_SHAKE_128F_SIMPLE: SphincsPlusShake128fSimpleScheme =
    SphincsPlusShake128fSimpleScheme;

impl SignatureScheme for SphincsPlusShake128fSimpleScheme {
    type PublicKey = sphincsshake128fsimple::PublicKey;
    type SecretKey = sphincsshake128fsimple::SecretKey;
    type SignedMessage = sphincsshake128fsimple::SignedMessage;

    fn algorithm_name(&self) -> &'static str {
        "SPHINCS+-SHAKE-128f-simple"
    }

    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey) {
        sphincsshake128fsimple::keypair()
    }

    fn sign(
        &self,
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Self::SignedMessage {
        sphincsshake128fsimple::sign(message, secret_key)
    }

    fn open(
        &self,
        signed_message: &Self::SignedMessage,
        public_key: &Self::PublicKey,
    ) -> Option<Vec<u8>> {
        sphincsshake128fsimple::open(signed_message, public_key).ok()
    }
}

pub fn bench_message(size: usize) -> Vec<u8> {
    vec![BENCH_MESSAGE_BYTE; size]
}

pub fn signature_size<S: SignedMessage>(
    signed_message: &S,
    message_len: usize,
) -> usize {
    signed_message.as_bytes().len().saturating_sub(message_len)
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
        bench_message, signature_size, SignatureScheme, BENCH_MESSAGE_BYTE,
        SPHINCS_PLUS_SHAKE_128F_SIMPLE,
    };

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let message = bench_message(16);
        assert_eq!(message.len(), 16);
        assert!(message.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }

    #[test]
    fn signature_size_subtracts_message_length() {
        struct FakeSigned(Vec<u8>);
        impl pqcrypto_traits::sign::SignedMessage for FakeSigned {
            fn from_bytes(
                bytes: &[u8],
            ) -> Result<Self, pqcrypto_traits::Error> {
                Ok(Self(bytes.to_vec()))
            }

            fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        let signed = FakeSigned(vec![0_u8; 42]);
        assert_eq!(signature_size(&signed, 10), 32);
        assert_eq!(signature_size(&signed, 100), 0);
    }

    #[test]
    fn sphincs_plus_sign_verify_roundtrip() {
        let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
        let message = b"sphincs-plus";
        let (public_key, secret_key) = scheme.keypair();
        let signed = scheme.sign(message, &secret_key);
        let opened = scheme
            .open(&signed, &public_key)
            .expect("verify should succeed");
        assert_eq!(opened, message);
    }
}
