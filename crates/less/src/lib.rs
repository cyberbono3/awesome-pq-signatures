pub use pq_bench::{
    bench_message, measure_time, signed_message_size, AllocationTracker,
    AllocationTrackingAllocator, BENCH_MESSAGE, BENCH_MESSAGE_BYTE,
    BENCH_MESSAGE_SIZES,
};
use std::ffi::{c_int, c_uchar, c_ulonglong};
use std::sync::Mutex;
pub const LESS_VARIANT: &str = "LESS-252-45";

const LESS_SEED_BYTES: usize = 16;
const KEYGEN_PROFILE: DeterministicRngProfile = DeterministicRngProfile {
    seed: *b"less--keygenseed",
    domain_separator: 0,
};
const SIGN_PROFILE: DeterministicRngProfile = DeterministicRngProfile {
    seed: *b"less--signing-se",
    domain_separator: 1,
};

static LESS_FFI_LOCK: Mutex<()> = Mutex::new(());
pq_bench::declare_tracking_allocator!();
pq_bench::declare_peak_memory_api!();

type LessSeed = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeterministicRngProfile {
    seed: LessSeed,
    domain_separator: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LessDimensions {
    public_key: usize,
    secret_key: usize,
    signature: usize,
}

struct NativeLess;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LessKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl LessKeyPair {
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
pub struct LessSignature(Vec<u8>);

impl LessSignature {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LessSizes {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LessError {
    FfiLockPoisoned,
    KeygenFailed(i32),
    SignFailed(i32),
    VerifyFailed(i32),
    InvalidSignedMessage,
    LengthOverflow,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LessScheme;

pub const LESS: LessScheme = LessScheme;

impl LessScheme {
    #[must_use]
    pub fn algorithm_name(&self) -> &'static str {
        LESS_VARIANT
    }

    /// # Errors
    ///
    /// Returns an error if the native LESS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn keypair(&self) -> Result<LessKeyPair, LessError> {
        self.keypair_with_seed(KEYGEN_PROFILE.seed)
    }

    /// # Errors
    ///
    /// Returns an error if the native LESS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn benchmark_keypair(&self) -> Result<LessKeyPair, LessError> {
        self.keypair()
    }

    /// # Errors
    ///
    /// Returns an error if the native LESS key generation call fails or if
    /// the native runtime lock is poisoned.
    pub fn keypair_with_seed(
        &self,
        seed: LessSeed,
    ) -> Result<LessKeyPair, LessError> {
        let profile = DeterministicRngProfile {
            seed,
            domain_separator: KEYGEN_PROFILE.domain_separator,
        };
        NativeLess::with_rng(profile, |_| NativeLess::keypair())
    }

    /// # Errors
    ///
    /// Returns an error if signing fails, the message length exceeds the native
    /// API width, or if the native runtime lock is poisoned.
    pub fn sign(
        &self,
        keypair: &LessKeyPair,
        message: &[u8],
    ) -> Result<LessSignature, LessError> {
        NativeLess::with_rng(SIGN_PROFILE, |_| {
            NativeLess::sign(keypair, message)
        })
    }

    /// # Errors
    ///
    /// Returns an error if signing fails, the message length exceeds the native
    /// API width, or if the native runtime lock is poisoned.
    pub fn sign_message(
        &self,
        keypair: &LessKeyPair,
        message: &[u8],
    ) -> Result<LessSignature, LessError> {
        self.sign(keypair, message)
    }

    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly, the message length
    /// exceeds the native API width, or if the native runtime lock is poisoned.
    pub fn verify(
        &self,
        keypair: &LessKeyPair,
        message: &[u8],
        signature: &LessSignature,
    ) -> Result<bool, LessError> {
        NativeLess::verify(keypair, message, signature)
    }

    /// # Errors
    ///
    /// Returns an error if verification fails unexpectedly, the message length
    /// exceeds the native API width, or if the native runtime lock is poisoned.
    pub fn verify_message(
        &self,
        keypair: &LessKeyPair,
        message: &[u8],
        signature: &LessSignature,
    ) -> Result<bool, LessError> {
        self.verify(keypair, message, signature)
    }

    #[must_use]
    pub fn public_key_size(&self, _keypair: &LessKeyPair) -> usize {
        NativeLess::dimensions().public_key
    }

    #[must_use]
    pub fn secret_key_size(&self, _keypair: &LessKeyPair) -> usize {
        NativeLess::dimensions().secret_key
    }

    #[must_use]
    pub fn signature_size(&self, _signature: &LessSignature) -> usize {
        NativeLess::dimensions().signature
    }

    #[must_use]
    pub fn sizes(
        &self,
        keypair: &LessKeyPair,
        signature: &LessSignature,
    ) -> LessSizes {
        LessSizes {
            public_key: self.public_key_size(keypair),
            secret_key: self.secret_key_size(keypair),
            signature: self.signature_size(signature),
        }
    }
}

impl NativeLess {
    fn dimensions() -> LessDimensions {
        LessDimensions {
            public_key: unsafe { less_rs_public_key_bytes() },
            secret_key: unsafe { less_rs_secret_key_bytes() },
            signature: unsafe { less_rs_signature_bytes() },
        }
    }

    fn with_rng<T, F>(
        profile: DeterministicRngProfile,
        operation: F,
    ) -> Result<T, LessError>
    where
        F: FnOnce(&Self) -> Result<T, LessError>,
    {
        let _guard = LESS_FFI_LOCK
            .lock()
            .map_err(|_| LessError::FfiLockPoisoned)?;
        init_rng(&profile);
        operation(&Self)
    }

    fn keypair() -> Result<LessKeyPair, LessError> {
        let dimensions = Self::dimensions();
        let mut public_key = vec![0_u8; dimensions.public_key];
        let mut secret_key = vec![0_u8; dimensions.secret_key];
        let rc = unsafe {
            crypto_sign_keypair(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
            )
        };

        if rc == 0 {
            Ok(LessKeyPair {
                public_key,
                secret_key,
            })
        } else {
            Err(LessError::KeygenFailed(rc))
        }
    }

    fn sign(
        keypair: &LessKeyPair,
        message: &[u8],
    ) -> Result<LessSignature, LessError> {
        let dimensions = Self::dimensions();
        let message_len = ulonglong_len(message.len())?;
        let mut signed_message =
            vec![
                0_u8;
                signed_message_size(message.len(), dimensions.signature)
            ];
        let mut signed_message_len = 0_u64;

        let rc = unsafe {
            crypto_sign(
                signed_message.as_mut_ptr(),
                &raw mut signed_message_len,
                message.as_ptr(),
                message_len,
                keypair.secret_key.as_ptr(),
            )
        };

        if rc != 0 {
            return Err(LessError::SignFailed(rc));
        }

        let signed_message_len = usize_len(signed_message_len)?;
        extract_signature(message.len(), &signed_message, signed_message_len)
    }

    fn verify(
        keypair: &LessKeyPair,
        message: &[u8],
        signature: &LessSignature,
    ) -> Result<bool, LessError> {
        let _guard = LESS_FFI_LOCK
            .lock()
            .map_err(|_| LessError::FfiLockPoisoned)?;

        let signed_message = combine_signed_message(message, signature);
        let signed_message_len = ulonglong_len(signed_message.len())?;
        let mut opened_message = vec![0_u8; message.len()];
        let mut opened_message_len = 0_u64;

        let rc = unsafe {
            crypto_sign_open(
                opened_message.as_mut_ptr(),
                &raw mut opened_message_len,
                signed_message.as_ptr(),
                signed_message_len,
                keypair.public_key.as_ptr(),
            )
        };

        match rc {
            0 => {
                let opened_message_len = usize_len(opened_message_len)?;
                Ok(matches_opened_message(
                    message,
                    &opened_message,
                    opened_message_len,
                ))
            }
            -1 => Ok(false),
            _ => Err(LessError::VerifyFailed(rc)),
        }
    }
}

fn init_rng(profile: &DeterministicRngProfile) {
    let seed_len =
        u32::try_from(LESS_SEED_BYTES).expect("less seed length fits in u32");
    unsafe {
        less_rs_init_rng(
            profile.seed.as_ptr(),
            seed_len,
            profile.domain_separator,
        );
    }
}

fn ulonglong_len(value: usize) -> Result<c_ulonglong, LessError> {
    c_ulonglong::try_from(value).map_err(|_| LessError::LengthOverflow)
}

fn usize_len(value: c_ulonglong) -> Result<usize, LessError> {
    usize::try_from(value).map_err(|_| LessError::LengthOverflow)
}

fn extract_signature(
    message_len: usize,
    signed_message: &[u8],
    signed_message_len: usize,
) -> Result<LessSignature, LessError> {
    signed_message
        .get(message_len..signed_message_len)
        .map(|bytes| LessSignature(bytes.to_vec()))
        .ok_or(LessError::InvalidSignedMessage)
}

fn combine_signed_message(
    message: &[u8],
    signature: &LessSignature,
) -> Vec<u8> {
    let mut signed_message = Vec::with_capacity(signed_message_size(
        message.len(),
        signature.0.len(),
    ));
    signed_message.extend_from_slice(message);
    signed_message.extend_from_slice(signature.as_bytes());
    signed_message
}

fn matches_opened_message(
    expected_message: &[u8],
    opened_message: &[u8],
    opened_message_len: usize,
) -> bool {
    opened_message_len == expected_message.len()
        && opened_message
            .get(..opened_message_len)
            .is_some_and(|message| message == expected_message)
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
    fn less_rs_init_rng(seed: *const c_uchar, seed_len: u32, dsc: u16);
    fn less_rs_public_key_bytes() -> usize;
    fn less_rs_secret_key_bytes() -> usize;
    fn less_rs_signature_bytes() -> usize;
}

#[cfg(test)]
mod tests {
    use super::{bench_message, signed_message_size, BENCH_MESSAGE_BYTE, LESS};

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
    fn less_sign_verify_roundtrip() {
        let scheme = LESS;
        let message = b"less";

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
