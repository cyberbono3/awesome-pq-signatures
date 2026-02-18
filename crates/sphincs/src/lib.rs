use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use gravity::{gravity_genpk, gravity_sign, gravity_verify, GravitySmall};

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
    type PublicKey;
    type SecretKey;
    type Signature;

    fn algorithm_name(&self) -> &'static str;
    fn backend_name(&self) -> &'static str;
    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey);
    fn sign(
        &self,
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Self::Signature;
    fn verify(
        &self,
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> bool;
    fn public_key_size(&self, public_key: &Self::PublicKey) -> usize;
    fn secret_key_size(&self, secret_key: &Self::SecretKey) -> usize;
    fn signature_size(&self, signature: &Self::Signature) -> usize;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SphincsScheme;

pub const SPHINCS_SCHEME: SphincsScheme = SphincsScheme;

impl SignatureScheme for SphincsScheme {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 64];
    type Signature = Vec<u8>;

    fn algorithm_name(&self) -> &'static str {
        "Gravity-SPHINCS (Small)"
    }

    fn backend_name(&self) -> &'static str {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            "gravity-rs"
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            "gravity-rs (unsupported on this architecture)"
        }
    }

    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey) {
        gravity_keypair()
    }

    fn sign(
        &self,
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Self::Signature {
        gravity_sign_bytes(secret_key, message)
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> bool {
        gravity_verify_bytes(public_key, message, signature)
    }

    fn public_key_size(&self, public_key: &Self::PublicKey) -> usize {
        public_key.len()
    }

    fn secret_key_size(&self, secret_key: &Self::SecretKey) -> usize {
        secret_key.len()
    }

    fn signature_size(&self, signature: &Self::Signature) -> usize {
        signature.len()
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn gravity_keypair() -> ([u8; 32], [u8; 64]) {
    let secret_key = [7_u8; 64];
    let mut public_key = [0_u8; 32];
    gravity_genpk::<GravitySmall>(&mut public_key, &secret_key);
    (public_key, secret_key)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn gravity_keypair() -> ([u8; 32], [u8; 64]) {
    panic!("gravity-rs is only available on x86/x86_64")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn gravity_sign_bytes(secret_key: &[u8; 64], message: &[u8]) -> Vec<u8> {
    gravity_sign::<GravitySmall>(secret_key, message)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn gravity_sign_bytes(_secret_key: &[u8; 64], _message: &[u8]) -> Vec<u8> {
    panic!("gravity-rs is only available on x86/x86_64")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn gravity_verify_bytes(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> bool {
    gravity_verify::<GravitySmall>(public_key, message, signature.to_vec())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn gravity_verify_bytes(
    _public_key: &[u8; 32],
    _message: &[u8],
    _signature: &[u8],
) -> bool {
    panic!("gravity-rs is only available on x86/x86_64")
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
        bench_message, signed_message_size, SignatureScheme,
        BENCH_MESSAGE_BYTE, SPHINCS_SCHEME,
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

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn sign_verify_roundtrip() {
        let scheme = SPHINCS_SCHEME;
        let (public_key, secret_key) = scheme.keypair();
        let message = b"sphincs";
        let signature = scheme.sign(message, &secret_key);
        assert!(scheme.verify(message, &signature, &public_key));
        assert!(scheme.public_key_size(&public_key) > 0);
        assert!(scheme.secret_key_size(&secret_key) > 0);
        assert!(scheme.signature_size(&signature) > 0);
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn backend_reports_unsupported() {
        let scheme = SPHINCS_SCHEME;
        assert_eq!(
            scheme.backend_name(),
            "gravity-rs (unsupported on this architecture)"
        );
    }
}
