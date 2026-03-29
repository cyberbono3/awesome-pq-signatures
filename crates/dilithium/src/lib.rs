use ml_dsa::{KeyGen, KeyPair, MlDsa65, Signature, B32};
pub use pq_bench::{
    bench_message, benchmark_seed_array, measure_time, signed_message_size,
    AllocationTracker, AllocationTrackingAllocator, BENCH_MESSAGE,
    BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
};
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

pub type MlDsaSeed = B32;
pub type MlDsaKeyPair = KeyPair<MlDsa65>;
pub type MlDsaSignature = Signature<MlDsa65>;

#[derive(Clone, Copy, Debug, Default)]
pub struct MlDsa65Scheme;

pub const ML_DSA_65: MlDsa65Scheme = MlDsa65Scheme;

impl MlDsa65Scheme {
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        "ML-DSA-65"
    }

    #[must_use]
    pub fn keypair(&self, seed: &MlDsaSeed) -> MlDsaKeyPair {
        MlDsa65::key_gen_internal(seed)
    }

    #[must_use]
    pub fn benchmark_keypair(&self) -> MlDsaKeyPair {
        self.keypair(&default_seed())
    }

    pub fn sign(
        &self,
        keypair: &MlDsaKeyPair,
        message: &[u8],
        context: &[u8],
    ) -> Result<MlDsaSignature, ml_dsa::Error> {
        keypair.signing_key().sign_deterministic(message, context)
    }

    #[must_use]
    pub fn verify(
        &self,
        keypair: &MlDsaKeyPair,
        message: &[u8],
        context: &[u8],
        signature: &MlDsaSignature,
    ) -> bool {
        keypair
            .verifying_key()
            .verify_with_context(message, context, signature)
    }

    #[must_use]
    pub fn public_key_size(&self, keypair: &MlDsaKeyPair) -> usize {
        keypair.verifying_key().encode().len()
    }

    #[must_use]
    pub fn secret_key_size(&self, keypair: &MlDsaKeyPair) -> usize {
        keypair.signing_key().encode().len()
    }

    #[must_use]
    pub fn signature_size(&self, signature: &MlDsaSignature) -> usize {
        signature.encode().len()
    }
}

#[must_use]
pub fn default_seed() -> MlDsaSeed {
    benchmark_seed_array::<32>().into()
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, default_seed, signed_message_size, BENCH_MESSAGE_BYTE,
        ML_DSA_65,
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
