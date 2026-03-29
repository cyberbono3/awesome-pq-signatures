use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use std::convert::Infallible;

pub use pq_bench::{
    bench_message, measure_time, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

pub type FalconKeyPair = (falcon512::PublicKey, falcon512::SecretKey);

#[derive(Clone)]
pub struct FalconSignature {
    signed_message: falcon512::SignedMessage,
    message_len: usize,
}

impl FalconSignature {
    #[must_use]
    pub fn signed_message(&self) -> &falcon512::SignedMessage {
        &self.signed_message
    }

    #[must_use]
    pub fn signed_message_len(&self) -> usize {
        self.signed_message.as_bytes().len()
    }

    #[must_use]
    pub fn detached_signature_len(&self) -> usize {
        signature_size(&self.signed_message, self.message_len)
    }
}

pq_bench::declare_simple_signed_message_scheme!(
    scheme_type = Falcon512Scheme,
    scheme_const = FALCON512,
    sizes_type = FalconSizes,
    keypair_type = FalconKeyPair,
    signature_type = FalconSignature,
    error_type = Infallible,
    variant = "Falcon-512",
    keygen = || Ok::<FalconKeyPair, Infallible>(falcon512::keypair()),
    sign = |keypair: &FalconKeyPair, message: &[u8]| {
        Ok::<FalconSignature, Infallible>(FalconSignature {
            signed_message: falcon512::sign(message, &keypair.1),
            message_len: message.len(),
        })
    },
    verify = |keypair: &FalconKeyPair,
              message: &[u8],
              signature: &FalconSignature| {
        Ok::<bool, Infallible>(matches!(
            falcon512::open(signature.signed_message(), &keypair.0),
            Ok(opened) if opened == message
        ))
    },
    public_key_size = |keypair: &FalconKeyPair| keypair.0.as_bytes().len(),
    secret_key_size = |keypair: &FalconKeyPair| keypair.1.as_bytes().len(),
    signature_size =
        |signature: &FalconSignature| signature.detached_signature_len()
);

pub fn signature_size<S: SignedMessage>(
    signed_message: &S,
    message_len: usize,
) -> usize {
    signed_message.as_bytes().len().saturating_sub(message_len)
}

#[cfg(test)]
mod tests {
    use super::{bench_message, signature_size, BENCH_MESSAGE_BYTE, FALCON512};

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
    fn falcon_sign_verify_roundtrip() {
        let scheme = FALCON512;
        let message = b"falcon";
        let keypair = scheme
            .benchmark_keypair()
            .expect("keypair generation should succeed");
        let signature = scheme
            .sign_message(&keypair, message)
            .expect("signing should succeed");

        assert!(scheme
            .verify_message(&keypair, message, &signature)
            .expect("verification should succeed"));

        let sizes = scheme.sizes(&keypair, &signature);
        assert!(sizes.public_key > 0);
        assert!(sizes.secret_key > 0);
        assert!(sizes.signature > 0);
    }
}
