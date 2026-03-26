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

type CrossSeed = [u8; CROSS_SEED_BYTES];

struct NativeCross;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl CrossKeyPair {
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    #[must_use]
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossSignature(Vec<u8>);

impl CrossSignature {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossError {
    FfiLockPoisoned,
    KeygenFailed(i32),
    SignFailed(i32),
    VerifyFailed(i32),
    InvalidSignedMessage,
    LengthOverflow,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CrossScheme;

pub const CROSS: CrossScheme = CrossScheme;

impl CrossScheme {
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        CROSS_VARIANT
    }

    /// # Errors
    ///
    /// Returns an error if the native CROSS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn keypair(&self) -> Result<CrossKeyPair, CrossError> {
        self.keypair_with_seed(KEYGEN_PROFILE.seed)
    }

    /// # Errors
    ///
    /// Returns an error if the native CROSS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn benchmark_keypair(&self) -> Result<CrossKeyPair, CrossError> {
        self.keypair()
    }

    /// # Errors
    ///
    /// Returns an error if the native CROSS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn keypair_with_seed(
        &self,
        seed: CrossSeed,
    ) -> Result<CrossKeyPair, CrossError> {
        let profile = DeterministicRngProfile {
            seed,
            domain_separator: KEYGEN_PROFILE.domain_separator,
        };
        ffi_deterministic_keypair(
            &CROSS_FFI_LOCK,
            profile,
            init_rng,
            NativeCross::dimensions(),
            |public_key, secret_key| unsafe {
                crypto_sign_keypair(public_key, secret_key)
            },
            |public_key, secret_key| CrossKeyPair {
                public_key,
                secret_key,
            },
            || CrossError::FfiLockPoisoned,
            CrossError::KeygenFailed,
        )
    }

    /// # Errors
    ///
    /// Returns an error if signing fails, the message length exceeds the native
    /// API width, or if the native runtime lock is poisoned.
    pub fn sign(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
    ) -> Result<CrossSignature, CrossError> {
        ffi_deterministic_sign(
            &CROSS_FFI_LOCK,
            SIGN_PROFILE,
            init_rng,
            NativeCross::dimensions(),
            message,
            &keypair.secret_key,
            |signed_message,
             signed_message_len,
             message,
             message_len,
             secret_key| unsafe {
                crypto_sign(
                    signed_message,
                    signed_message_len,
                    message,
                    message_len,
                    secret_key,
                )
            },
            CrossSignature,
            || CrossError::FfiLockPoisoned,
            CrossError::SignFailed,
            || CrossError::LengthOverflow,
            || CrossError::InvalidSignedMessage,
        )
    }

    /// # Errors
    ///
    /// Returns an error if signing fails, the message length exceeds the native
    /// API width, or if the native runtime lock is poisoned.
    pub fn sign_message(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
    ) -> Result<CrossSignature, CrossError> {
        self.sign(keypair, message)
    }

    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly, the message length
    /// exceeds the native API width, or if the native runtime lock is poisoned.
    pub fn verify(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
        signature: &CrossSignature,
    ) -> Result<bool, CrossError> {
        ffi_locked_verify(
            &CROSS_FFI_LOCK,
            message,
            signature.as_bytes(),
            &keypair.public_key,
            |opened_message,
             opened_message_len,
             signed_message,
             signed_message_len,
             public_key| unsafe {
                crypto_sign_open(
                    opened_message,
                    opened_message_len,
                    signed_message,
                    signed_message_len,
                    public_key,
                )
            },
            || CrossError::FfiLockPoisoned,
            CrossError::VerifyFailed,
            || CrossError::LengthOverflow,
        )
    }

    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly, the message length
    /// exceeds the native API width, or if the native runtime lock is poisoned.
    pub fn verify_message(
        &self,
        keypair: &CrossKeyPair,
        message: &[u8],
        signature: &CrossSignature,
    ) -> Result<bool, CrossError> {
        self.verify(keypair, message, signature)
    }

    #[must_use]
    pub fn public_key_size(&self, _keypair: &CrossKeyPair) -> usize {
        NativeCross::dimensions().public_key
    }

    #[must_use]
    pub fn secret_key_size(&self, _keypair: &CrossKeyPair) -> usize {
        NativeCross::dimensions().secret_key
    }

    #[must_use]
    pub fn signature_size(&self, _signature: &CrossSignature) -> usize {
        NativeCross::dimensions().signature
    }

    #[must_use]
    pub fn sizes(
        &self,
        keypair: &CrossKeyPair,
        signature: &CrossSignature,
    ) -> CrossSizes {
        CrossSizes {
            public_key: self.public_key_size(keypair),
            secret_key: self.secret_key_size(keypair),
            signature: self.signature_size(signature),
        }
    }
}

impl NativeCross {
    fn dimensions() -> FfiSignedMessageDimensions {
        FfiSignedMessageDimensions {
            public_key: unsafe { cross_rs_public_key_bytes() },
            secret_key: unsafe { cross_rs_secret_key_bytes() },
            signature: unsafe { cross_rs_signature_bytes() },
        }
    }
}

fn init_rng(profile: &DeterministicRngProfile<CROSS_SEED_BYTES>) {
    let seed_len =
        u32::try_from(CROSS_SEED_BYTES).expect("cross seed length fits in u32");
    unsafe {
        cross_rs_init_rng(
            profile.seed.as_ptr(),
            seed_len,
            profile.domain_separator,
        );
    }
}

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
