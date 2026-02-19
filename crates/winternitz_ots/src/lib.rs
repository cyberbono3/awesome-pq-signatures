use blake2_rfc::blake2b::blake2b;
use std::alloc::{GlobalAlloc, Layout};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use winternitz_ots_lib::wots::{self, Wots, WotsSignature};

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
    type Keypair;
    type Signature;

    fn algorithm_name(&self) -> &'static str;
    fn backend_name(&self) -> &'static str;
    fn param_set_name(&self) -> &'static str;
    fn keypair(&self) -> Self::Keypair;
    fn sign(&self, keypair: &Self::Keypair, message: &[u8]) -> Self::Signature;
    fn verify(&self, signature: &Self::Signature) -> bool;
    fn public_key_size(&self, keypair: &Self::Keypair) -> usize;
    fn secret_key_size(&self, keypair: &Self::Keypair) -> usize;
    fn signature_size(&self, signature: &Self::Signature) -> usize;
    fn signed_input_size(&self, signature: &Self::Signature) -> usize;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WinternitzOtsScheme;

pub const WINTERNITZ_OTS: WinternitzOtsScheme = WinternitzOtsScheme;

impl SignatureScheme for WinternitzOtsScheme {
    type Keypair = Wots;
    type Signature = WotsSignature;

    fn algorithm_name(&self) -> &'static str {
        "Winternitz OTS (W-OTS)"
    }

    fn backend_name(&self) -> &'static str {
        "winternitz-ots-0.3.0"
    }

    fn param_set_name(&self) -> &'static str {
        "w=16,n=32,hash=blake2b"
    }

    fn keypair(&self) -> Self::Keypair {
        wots::generate_wots()
    }

    fn sign(&self, keypair: &Self::Keypair, message: &[u8]) -> Self::Signature {
        keypair.sign(message_digest_hex(message))
    }

    fn verify(&self, signature: &Self::Signature) -> bool {
        std::panic::catch_unwind(AssertUnwindSafe(|| signature.verify()))
            .unwrap_or(false)
    }

    fn public_key_size(&self, keypair: &Self::Keypair) -> usize {
        hex_vec_byte_len(&keypair.pk)
    }

    fn secret_key_size(&self, keypair: &Self::Keypair) -> usize {
        hex_vec_byte_len(&keypair.sk)
    }

    fn signature_size(&self, signature: &Self::Signature) -> usize {
        hex_vec_byte_len(&signature.signature)
    }

    fn signed_input_size(&self, signature: &Self::Signature) -> usize {
        hex_string_byte_len(&signature.input)
    }
}

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

pub fn message_digest_hex(message: &[u8]) -> String {
    let digest = blake2b(32, &[], message);
    hex::encode_upper(digest.as_bytes())
}

fn hex_vec_byte_len(values: &[String]) -> usize {
    values.iter().map(|value| hex_string_byte_len(value)).sum()
}

fn hex_string_byte_len(value: &str) -> usize {
    value.len() / 2
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, message_digest_hex, SignatureScheme, BENCH_MESSAGE_BYTE,
        WINTERNITZ_OTS,
    };

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let message = bench_message(16);
        assert_eq!(message.len(), 16);
        assert!(message.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }

    #[test]
    fn digest_has_expected_size() {
        let digest = message_digest_hex(b"digest-test");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let scheme = WINTERNITZ_OTS;
        let keypair = scheme.keypair();
        let signature = scheme.sign(&keypair, b"hello winternitz");
        assert!(scheme.verify(&signature));
    }

    #[test]
    fn verify_returns_false_for_tampered_signature() {
        let scheme = WINTERNITZ_OTS;
        let keypair = scheme.keypair();
        let mut signature = scheme.sign(&keypair, b"tamper");
        signature.pk[0] = "00".repeat(32);
        assert!(!scheme.verify(&signature));
    }
}
