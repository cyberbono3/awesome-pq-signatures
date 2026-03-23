use blake2_rfc::blake2b::blake2b;
use std::panic::AssertUnwindSafe;
use winternitz_ots_lib::wots::{self, Wots, WotsSignature};

pub use pq_bench::{
    bench_message, measure_time, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
pub static ALLOCATION_TRACKER: AllocationTracker = AllocationTracker::new();
pub type TrackingAllocator<A> = AllocationTrackingAllocator<A>;

pub mod memory {
    use super::ALLOCATION_TRACKER;

    pub fn reset_peak() {
        ALLOCATION_TRACKER.reset_peak();
    }

    pub fn peak_bytes() -> usize {
        ALLOCATION_TRACKER.peak_bytes()
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
