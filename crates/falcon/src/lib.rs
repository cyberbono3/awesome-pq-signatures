use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

pub use pq_bench::{
    bench_message, measure_time, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

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
pub struct Falcon512Scheme;

pub const FALCON512: Falcon512Scheme = Falcon512Scheme;

impl SignatureScheme for Falcon512Scheme {
    type PublicKey = falcon512::PublicKey;
    type SecretKey = falcon512::SecretKey;
    type SignedMessage = falcon512::SignedMessage;

    fn algorithm_name(&self) -> &'static str {
        "Falcon-512"
    }

    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey) {
        falcon512::keypair()
    }

    fn sign(
        &self,
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Self::SignedMessage {
        falcon512::sign(message, secret_key)
    }

    fn open(
        &self,
        signed_message: &Self::SignedMessage,
        public_key: &Self::PublicKey,
    ) -> Option<Vec<u8>> {
        falcon512::open(signed_message, public_key).ok()
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
    use super::{bench_message, signature_size, BENCH_MESSAGE_BYTE};

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
}
