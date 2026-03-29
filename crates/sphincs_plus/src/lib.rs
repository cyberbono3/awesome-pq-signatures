pub use pq_bench::{
    bench_message, measure_time, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
use pqcrypto_sphincsplus::sphincsshake128fsimple;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use std::convert::Infallible;
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

pub type SphincsPlusKeyPair = (
    sphincsshake128fsimple::PublicKey,
    sphincsshake128fsimple::SecretKey,
);

#[derive(Clone)]
pub struct SphincsPlusSignature {
    signed_message: sphincsshake128fsimple::SignedMessage,
    message_len: usize,
}

impl SphincsPlusSignature {
    #[must_use]
    pub fn signed_message(&self) -> &sphincsshake128fsimple::SignedMessage {
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
    scheme_type = SphincsPlusShake128fSimpleScheme,
    scheme_const = SPHINCS_PLUS_SHAKE_128F_SIMPLE,
    sizes_type = SphincsPlusSizes,
    keypair_type = SphincsPlusKeyPair,
    signature_type = SphincsPlusSignature,
    error_type = Infallible,
    variant = "SPHINCS+-SHAKE-128f-simple",
    keygen = || {
        Ok::<SphincsPlusKeyPair, Infallible>(sphincsshake128fsimple::keypair())
    },
    sign = |keypair: &SphincsPlusKeyPair, message: &[u8]| {
        Ok::<SphincsPlusSignature, Infallible>(SphincsPlusSignature {
            signed_message: sphincsshake128fsimple::sign(message, &keypair.1),
            message_len: message.len(),
        })
    },
    verify = |keypair: &SphincsPlusKeyPair,
              message: &[u8],
              signature: &SphincsPlusSignature| {
        Ok::<bool, Infallible>(matches!(
            sphincsshake128fsimple::open(signature.signed_message(), &keypair.0),
            Ok(opened) if opened == message
        ))
    },
    public_key_size = |keypair: &SphincsPlusKeyPair| keypair.0.as_bytes().len(),
    secret_key_size = |keypair: &SphincsPlusKeyPair| keypair.1.as_bytes().len(),
    signature_size =
        |signature: &SphincsPlusSignature| signature.detached_signature_len()
);

pub fn signature_size<S: SignedMessage>(
    signed_message: &S,
    message_len: usize,
) -> usize {
    signed_message.as_bytes().len().saturating_sub(message_len)
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, signature_size, BENCH_MESSAGE_BYTE,
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
