use ml_dsa::{KeyGen, KeyPair, MlDsa65, Signature, B32};
pub use pq_bench::{
    bench_message, benchmark_seed_array, measure_time, signed_message_size,
    AllocationTracker, AllocationTrackingAllocator, BENCH_MESSAGE,
    BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
};
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

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
    benchmark_seed_array::<32>().into()
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
