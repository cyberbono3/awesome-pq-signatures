pub use pq_bench::{
    bench_message, measure_time, signed_message_size, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
use sqisign_lvl1::{KeyPair, Signature as RawSqisignSignature, SqisignError};
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

pub type SqisignKeyPair = KeyPair;
pub type SqisignSignature = RawSqisignSignature;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqisignSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SqisignScheme;

pub const SQISIGN: SqisignScheme = SqisignScheme;

impl SqisignScheme {
    pub fn algorithm_name(&self) -> &'static str {
        "SQISign"
    }

    pub fn keypair(&self) -> Result<SqisignKeyPair, SqisignError> {
        SqisignKeyPair::generate()
    }

    pub fn benchmark_keypair(&self) -> Result<SqisignKeyPair, SqisignError> {
        self.keypair()
    }

    pub fn sign(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
    ) -> Result<SqisignSignature, SqisignError> {
        keypair.sign(message)
    }

    pub fn sign_message(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
    ) -> Result<SqisignSignature, SqisignError> {
        self.sign(keypair, message)
    }

    pub fn verify(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
        signature: &SqisignSignature,
    ) -> Result<bool, SqisignError> {
        keypair.verify(message, signature)
    }

    pub fn verify_message(
        &self,
        keypair: &SqisignKeyPair,
        message: &[u8],
        signature: &SqisignSignature,
    ) -> Result<bool, SqisignError> {
        self.verify(keypair, message, signature)
    }

    pub fn public_key_size(&self, keypair: &SqisignKeyPair) -> usize {
        keypair.public_key.as_bytes().len()
    }

    pub fn secret_key_size(&self, keypair: &SqisignKeyPair) -> usize {
        keypair.secret_key.as_bytes().len()
    }

    pub fn signature_size(&self, signature: &SqisignSignature) -> usize {
        signature.as_bytes().len()
    }

    pub fn sizes(
        &self,
        keypair: &SqisignKeyPair,
        signature: &SqisignSignature,
    ) -> SqisignSizes {
        SqisignSizes {
            public_key: self.public_key_size(keypair),
            secret_key: self.secret_key_size(keypair),
            signature: self.signature_size(signature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, signed_message_size, BENCH_MESSAGE_BYTE, SQISIGN,
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
    fn sqisign_sign_verify_roundtrip() {
        let scheme = SQISIGN;
        let message = b"sqisign";

        let keypair = scheme
            .benchmark_keypair()
            .expect("keypair generation should succeed");
        let signature = scheme
            .sign_message(&keypair, message)
            .expect("signing should succeed");
        let verified = scheme
            .verify_message(&keypair, message, &signature)
            .expect("verification should succeed");
        assert!(verified, "signature verification should succeed");

        let sizes = scheme.sizes(&keypair, &signature);
        assert!(sizes.public_key > 0);
        assert!(sizes.secret_key > 0);
        assert!(sizes.signature > 0);
    }
}
