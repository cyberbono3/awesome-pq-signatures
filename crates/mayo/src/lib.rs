pub use pq_bench::{
    bench_message, benchmark_seed_array, measure_time, signed_message_size,
    AllocationTracker, AllocationTrackingAllocator, BENCH_MESSAGE,
    BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
};
use pq_mayo::{KeyPair, Mayo1, Signature as RawMayoSignature};
use signature::{Error as SignatureError, Signer, Verifier};
pub const DEFAULT_CONTEXT: &[u8] = &[];
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

pub type MayoSeed = [u8; 24];
pub type MayoKeyPair = KeyPair<Mayo1>;
pub type MayoSignature = RawMayoSignature<Mayo1>;

#[derive(Clone, Copy, Debug, Default)]
pub struct MayoSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Debug)]
pub enum MayoError {
    UnsupportedContext,
    Crypto(SignatureError),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MayoScheme;

pub const MAYO: MayoScheme = MayoScheme;

impl MayoScheme {
    pub fn algorithm_name(&self) -> &'static str {
        "MAYO"
    }

    pub fn keypair(&self, seed: &MayoSeed) -> MayoKeyPair {
        MayoKeyPair::from_seed(seed)
            .expect("MAYO key generation from seed should succeed")
    }

    pub fn benchmark_keypair(&self) -> MayoKeyPair {
        self.keypair(&default_seed())
    }

    pub fn sign(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
        context: &[u8],
    ) -> Result<MayoSignature, MayoError> {
        self.ensure_context_supported(context)?;

        keypair
            .signing_key()
            .try_sign(message)
            .map_err(MayoError::Crypto)
    }

    pub fn sign_message(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
    ) -> Result<MayoSignature, MayoError> {
        self.sign(keypair, message, DEFAULT_CONTEXT)
    }

    pub fn verify(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
        context: &[u8],
        signature: &MayoSignature,
    ) -> bool {
        if self.ensure_context_supported(context).is_err() {
            return false;
        }

        keypair.verifying_key().verify(message, signature).is_ok()
    }

    pub fn verify_message(
        &self,
        keypair: &MayoKeyPair,
        message: &[u8],
        signature: &MayoSignature,
    ) -> bool {
        self.verify(keypair, message, DEFAULT_CONTEXT, signature)
    }

    pub fn public_key_size(&self, keypair: &MayoKeyPair) -> usize {
        keypair.verifying_key().as_ref().len()
    }

    pub fn secret_key_size(&self, keypair: &MayoKeyPair) -> usize {
        keypair.signing_key().as_ref().len()
    }

    pub fn signature_size(&self, signature: &MayoSignature) -> usize {
        signature.as_ref().len()
    }

    pub fn sizes(
        &self,
        keypair: &MayoKeyPair,
        signature: &MayoSignature,
    ) -> MayoSizes {
        MayoSizes {
            public_key_bytes: self.public_key_size(keypair),
            secret_key_bytes: self.secret_key_size(keypair),
            signature_bytes: self.signature_size(signature),
        }
    }

    fn ensure_context_supported(
        &self,
        context: &[u8],
    ) -> Result<(), MayoError> {
        if context.is_empty() {
            Ok(())
        } else {
            Err(MayoError::UnsupportedContext)
        }
    }
}

pub fn default_seed() -> MayoSeed {
    benchmark_seed_array::<24>()
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, default_seed, signed_message_size, BENCH_MESSAGE_BYTE,
        MAYO,
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
    fn mayo_sign_verify_roundtrip() {
        let scheme = MAYO;
        let seed = default_seed();
        let message = b"mayo";

        let keypair = scheme.keypair(&seed);
        let signature = scheme
            .sign_message(&keypair, message)
            .expect("signing should succeed");
        let verified = scheme.verify_message(&keypair, message, &signature);
        assert!(verified, "signature verification should succeed");
    }
}
