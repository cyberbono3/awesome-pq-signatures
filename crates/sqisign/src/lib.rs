pub use pq_bench::{
    bench_message, measure_time, signed_message_size, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
use sqisign_lvl1::{KeyPair, Signature as RawSqisignSignature, SqisignError};
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

pub type SqisignKeyPair = KeyPair;
pub type SqisignSignature = RawSqisignSignature;
pq_bench::declare_simple_signed_message_scheme!(
    scheme_type = SqisignScheme,
    scheme_const = SQISIGN,
    sizes_type = SqisignSizes,
    keypair_type = SqisignKeyPair,
    signature_type = SqisignSignature,
    error_type = SqisignError,
    variant = "SQISign",
    keygen = || SqisignKeyPair::generate(),
    sign = |keypair: &SqisignKeyPair, message: &[u8]| keypair.sign(message),
    verify = |keypair: &SqisignKeyPair,
              message: &[u8],
              signature: &SqisignSignature| keypair
        .verify(message, signature),
    public_key_size =
        |keypair: &SqisignKeyPair| keypair.public_key.as_bytes().len(),
    secret_key_size =
        |keypair: &SqisignKeyPair| keypair.secret_key.as_bytes().len(),
    signature_size = |signature: &SqisignSignature| signature.as_bytes().len()
);

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
