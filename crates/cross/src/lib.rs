pub use pq_bench::{
    bench_message, ffi_keypair, ffi_sign, ffi_verify, measure_time,
    signed_message_size, with_deterministic_rng, with_ffi_lock,
    AllocationTracker, AllocationTrackingAllocator, FfiSignedMessageDimensions,
    BENCH_MESSAGE, BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
};
use std::ffi::{c_int, c_uchar, c_ulonglong};
use std::sync::Mutex;
pub const CROSS_VARIANT: &str = "CROSS-RSDPG-192-BALANCED";

const CROSS_SEED_BYTES: usize = 16;
const KEYGEN_PROFILE: DeterministicRngProfile = DeterministicRngProfile {
    seed: *b"cross-keygenseed",
    domain_separator: 0,
};
const SIGN_PROFILE: DeterministicRngProfile = DeterministicRngProfile {
    seed: *b"cross-signing-se",
    domain_separator: 1,
};

static CROSS_FFI_LOCK: Mutex<()> = Mutex::new(());
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

type CrossSeed = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeterministicRngProfile {
    seed: CrossSeed,
    domain_separator: u16,
}

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
        NativeCross::with_rng(profile, |_| NativeCross::keypair())
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
        NativeCross::with_rng(SIGN_PROFILE, |_| {
            NativeCross::sign(keypair, message)
        })
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
        NativeCross::verify(keypair, message, signature)
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

    fn with_rng<T, F>(
        profile: DeterministicRngProfile,
        operation: F,
    ) -> Result<T, CrossError>
    where
        F: FnOnce(&Self) -> Result<T, CrossError>,
    {
        with_deterministic_rng(
            &CROSS_FFI_LOCK,
            || CrossError::FfiLockPoisoned,
            || init_rng(&profile),
            || operation(&Self),
        )
    }

    fn keypair() -> Result<CrossKeyPair, CrossError> {
        ffi_keypair(
            Self::dimensions(),
            |public_key, secret_key| unsafe {
                crypto_sign_keypair(public_key, secret_key)
            },
            |public_key, secret_key| CrossKeyPair {
                public_key,
                secret_key,
            },
            CrossError::KeygenFailed,
        )
    }

    fn sign(
        keypair: &CrossKeyPair,
        message: &[u8],
    ) -> Result<CrossSignature, CrossError> {
        ffi_sign(
            Self::dimensions(),
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
            CrossError::SignFailed,
            || CrossError::LengthOverflow,
            || CrossError::InvalidSignedMessage,
        )
    }

    fn verify(
        keypair: &CrossKeyPair,
        message: &[u8],
        signature: &CrossSignature,
    ) -> Result<bool, CrossError> {
        with_ffi_lock(
            &CROSS_FFI_LOCK,
            || CrossError::FfiLockPoisoned,
            || {
                ffi_verify(
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
                    CrossError::VerifyFailed,
                    || CrossError::LengthOverflow,
                )
            },
        )
    }
}

fn init_rng(profile: &DeterministicRngProfile) {
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
