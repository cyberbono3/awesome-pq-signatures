pub use pq_bench::{
    bench_message, measure_time, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
use pqcrypto_sphincsplus::sphincsshake128fsimple;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
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

pub fn signature_size<S: SignedMessage>(
    signed_message: &S,
    message_len: usize,
) -> usize {
    signed_message.as_bytes().len().saturating_sub(message_len)
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
