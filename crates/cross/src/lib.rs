pub use pq_bench::{
    bench_message, ffi_deterministic_keypair, ffi_deterministic_sign,
    ffi_keypair, ffi_locked_verify, ffi_sign, ffi_verify, measure_time,
    signed_message_size, AllocationTracker, AllocationTrackingAllocator,
    DeterministicRngProfile, FfiSignedMessageDimensions, BENCH_MESSAGE,
    BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
};
use std::ffi::{c_int, c_uchar, c_ulonglong};
use std::sync::Mutex;
pub const CROSS_VARIANT: &str = "CROSS-RSDPG-192-BALANCED";

const CROSS_SEED_BYTES: usize = 16;
const KEYGEN_PROFILE: DeterministicRngProfile<CROSS_SEED_BYTES> =
    DeterministicRngProfile {
        seed: *b"cross-keygenseed",
        domain_separator: 0,
    };
const SIGN_PROFILE: DeterministicRngProfile<CROSS_SEED_BYTES> =
    DeterministicRngProfile {
        seed: *b"cross-signing-se",
        domain_separator: 1,
    };

static CROSS_FFI_LOCK: Mutex<()> = Mutex::new(());
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();
pq_bench::declare_ffi_signed_message_backend!(
    native_type = NativeCross,
    init_rng = init_rng,
    seed_bytes = CROSS_SEED_BYTES,
    seed_length_error = "cross seed length fits in u32",
    init_rng_fn = cross_rs_init_rng,
    public_key_bytes_fn = cross_rs_public_key_bytes,
    secret_key_bytes_fn = cross_rs_secret_key_bytes,
    signature_bytes_fn = cross_rs_signature_bytes
);

pq_bench::declare_ffi_signed_message_scheme!(
    seed_type = CrossSeed,
    scheme_type = CrossScheme,
    scheme_const = CROSS,
    keypair_type = CrossKeyPair,
    signature_type = CrossSignature,
    sizes_type = CrossSizes,
    error_type = CrossError,
    variant = CROSS_VARIANT,
    seed_bytes = CROSS_SEED_BYTES,
    keygen_profile = KEYGEN_PROFILE,
    sign_profile = SIGN_PROFILE,
    ffi_lock = CROSS_FFI_LOCK,
    dimensions = NativeCross::dimensions(),
    init_rng = init_rng,
    keypair_fn = crypto_sign_keypair,
    sign_fn = crypto_sign,
    verify_fn = crypto_sign_open
);

unsafe extern "C" {
    fn crypto_sign_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
    fn crypto_sign(
        sm: *mut c_uchar,
        smlen: *mut c_ulonglong,
        m: *const c_uchar,
        mlen: c_ulonglong,
        sk: *const c_uchar,
    ) -> c_int;
    fn crypto_sign_open(
        m: *mut c_uchar,
        mlen: *mut c_ulonglong,
        sm: *const c_uchar,
        smlen: c_ulonglong,
        pk: *const c_uchar,
    ) -> c_int;
    fn cross_rs_init_rng(seed: *const c_uchar, seed_len: u32, dsc: u16);
    fn cross_rs_public_key_bytes() -> usize;
    fn cross_rs_secret_key_bytes() -> usize;
    fn cross_rs_signature_bytes() -> usize;
}

#[cfg(test)]
mod tests {
    use super::{
        bench_message, signed_message_size, BENCH_MESSAGE_BYTE, CROSS,
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
    fn cross_sign_verify_roundtrip() {
        let scheme = CROSS;
        let message = b"cross";

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
