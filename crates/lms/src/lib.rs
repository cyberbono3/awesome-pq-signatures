use hbs_lms::{
    keygen,
    signature::{SignerMut, Verifier},
    HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256,
    Signature as RawSignature, SigningKey as RawSigningKey,
    VerifyingKey as RawVerifyingKey,
};
use std::error::Error;
use std::fmt;

pub use pq_bench::{
    bench_message, benchmark_seed_u64, measure_time, signed_message_size,
    AllocationTracker, AllocationTrackingAllocator, BENCH_MESSAGE,
    BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
};
pub const DEFAULT_PARAM_SET_NAME: &str =
    "LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4";
pq_bench::declare_tracking_allocator!();

const LMS_PUBLIC_KEY_BYTES: usize = 56;
const LMS_SECRET_KEY_BYTES: usize = 48;
const SHA256_OUTPUT_BYTES: usize = 32;
const LMOTS_W4_CHAIN_COUNT: usize = 67;

type Hasher = Sha256_256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LmsParamSet {
    H5W4,
    H10W4,
}

impl LmsParamSet {
    pub const fn name(self) -> &'static str {
        match self {
            Self::H5W4 => "LMS-SHA256-M32-H5+LMOTS-SHA256-N32-W4",
            Self::H10W4 => "LMS-SHA256-M32-H10+LMOTS-SHA256-N32-W4",
        }
    }

    pub const fn tree_height(self) -> usize {
        match self {
            Self::H5W4 => 5,
            Self::H10W4 => 10,
        }
    }

    pub const fn max_signatures(self) -> u32 {
        1u32 << self.tree_height()
    }

    pub const fn signature_size_bytes(self) -> usize {
        16 + SHA256_OUTPUT_BYTES
            * (1 + LMOTS_W4_CHAIN_COUNT + self.tree_height())
    }

    fn lms_algorithm(self) -> LmsAlgorithm {
        match self {
            Self::H5W4 => LmsAlgorithm::LmsH5,
            Self::H10W4 => LmsAlgorithm::LmsH10,
        }
    }

    fn parameters(self) -> [HssParameter<Hasher>; 1] {
        [HssParameter::new(
            LmotsAlgorithm::LmotsW4,
            self.lms_algorithm(),
        )]
    }
}

pub const LMS_PARAM_SETS: [LmsParamSet; 2] =
    [LmsParamSet::H5W4, LmsParamSet::H10W4];

pub fn param_set_by_name(name: &str) -> Option<LmsParamSet> {
    LMS_PARAM_SETS
        .iter()
        .copied()
        .find(|param_set| param_set.name() == name)
}

pub struct LmsPublicKey {
    params: LmsParamSet,
    key: RawVerifyingKey<Hasher>,
}

impl LmsPublicKey {
    pub fn param_set(&self) -> LmsParamSet {
        self.params
    }
}

pub struct LmsSecretKey {
    params: LmsParamSet,
    key: RawSigningKey<Hasher>,
}

impl LmsSecretKey {
    pub fn param_set(&self) -> LmsParamSet {
        self.params
    }

    pub fn remaining_signatures(&self) -> Result<u32, LmsError> {
        self.key
            .get_lifetime()
            .map(|value| value as u32)
            .map_err(|_| LmsError::StateReadFailed)
    }

    pub fn used_signatures(&self) -> Result<u32, LmsError> {
        let remaining = self.remaining_signatures()?;
        Ok(self.param_set().max_signatures().saturating_sub(remaining))
    }
}

pub struct LmsSignature {
    params: LmsParamSet,
    signature: RawSignature,
}

impl LmsSignature {
    pub fn param_set(&self) -> LmsParamSet {
        self.params
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LmsSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LmsScheme {
    params: LmsParamSet,
}

impl LmsScheme {
    pub fn new(params: LmsParamSet) -> Self {
        Self { params }
    }

    pub fn from_param_set_name(name: &str) -> Result<Self, LmsError> {
        let params = param_set_by_name(name).ok_or_else(|| {
            LmsError::UnknownParamSet {
                name: name.to_owned(),
            }
        })?;
        Ok(Self::new(params))
    }

    pub fn algorithm_name(&self) -> &'static str {
        "LMS"
    }

    pub fn backend_name(&self) -> &'static str {
        "hbs-lms"
    }

    pub fn param_set_name(&self) -> &'static str {
        self.params.name()
    }

    pub fn tree_height(&self) -> usize {
        self.params.tree_height()
    }

    pub fn max_signatures_per_key(&self) -> u32 {
        self.params.max_signatures()
    }

    pub fn sizes(&self) -> LmsSizes {
        LmsSizes {
            public_key_bytes: LMS_PUBLIC_KEY_BYTES,
            secret_key_bytes: LMS_SECRET_KEY_BYTES,
            signature_bytes: self.params.signature_size_bytes(),
        }
    }

    pub fn keypair(&self) -> Result<(LmsPublicKey, LmsSecretKey), LmsError> {
        let seed = default_seed();
        self.keypair_with_seed(seed)
    }

    pub fn keypair_with_seed(
        &self,
        seed_value: u64,
    ) -> Result<(LmsPublicKey, LmsSecretKey), LmsError> {
        let mut seed = Seed::<Hasher>::default();
        seed.as_mut_slice()
            .copy_from_slice(&seed_material_from_u64(seed_value));

        let (secret_key, public_key) =
            keygen::<Hasher>(&self.params.parameters(), &seed, None)
                .map_err(|_| LmsError::KeygenFailed)?;

        Ok((
            LmsPublicKey {
                params: self.params,
                key: public_key,
            },
            LmsSecretKey {
                params: self.params,
                key: secret_key,
            },
        ))
    }

    pub fn sign(
        &self,
        message: &[u8],
        secret_key: &mut LmsSecretKey,
    ) -> Result<LmsSignature, LmsError> {
        self.ensure_secret_key_params(secret_key)?;
        let signature = secret_key
            .key
            .try_sign(message)
            .map_err(|_| LmsError::SignFailed)?;

        Ok(LmsSignature {
            params: self.params,
            signature,
        })
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &LmsSignature,
        public_key: &LmsPublicKey,
    ) -> Result<bool, LmsError> {
        self.ensure_public_key_params(public_key)?;
        self.ensure_signature_params(signature)?;
        Ok(public_key.key.verify(message, &signature.signature).is_ok())
    }

    pub fn public_key_size(&self, public_key: &LmsPublicKey) -> usize {
        public_key.key.as_slice().len()
    }

    pub fn secret_key_size(&self, secret_key: &LmsSecretKey) -> usize {
        secret_key.key.as_slice().len()
    }

    pub fn signature_size(&self, signature: &LmsSignature) -> usize {
        signature.signature.as_ref().len()
    }

    pub fn remaining_signatures(
        &self,
        secret_key: &LmsSecretKey,
    ) -> Result<u32, LmsError> {
        self.ensure_secret_key_params(secret_key)?;
        secret_key.remaining_signatures()
    }

    fn ensure_secret_key_params(
        &self,
        secret_key: &LmsSecretKey,
    ) -> Result<(), LmsError> {
        if secret_key.param_set() != self.params {
            return Err(LmsError::ParamSetMismatch {
                expected: self.params.name(),
                actual: secret_key.param_set().name(),
            });
        }
        Ok(())
    }

    fn ensure_public_key_params(
        &self,
        public_key: &LmsPublicKey,
    ) -> Result<(), LmsError> {
        if public_key.param_set() != self.params {
            return Err(LmsError::ParamSetMismatch {
                expected: self.params.name(),
                actual: public_key.param_set().name(),
            });
        }
        Ok(())
    }

    fn ensure_signature_params(
        &self,
        signature: &LmsSignature,
    ) -> Result<(), LmsError> {
        if signature.param_set() != self.params {
            return Err(LmsError::ParamSetMismatch {
                expected: self.params.name(),
                actual: signature.param_set().name(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmsError {
    UnknownParamSet {
        name: String,
    },
    ParamSetMismatch {
        expected: &'static str,
        actual: &'static str,
    },
    KeygenFailed,
    SignFailed,
    VerifyFailed,
    StateReadFailed,
}

impl fmt::Display for LmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParamSet { name } => {
                write!(f, "unknown LMS param set: {name}")
            }
            Self::ParamSetMismatch { expected, actual } => {
                write!(
                    f,
                    "parameter set mismatch: expected {expected}, got {actual}"
                )
            }
            Self::KeygenFailed => write!(f, "LMS key generation failed"),
            Self::SignFailed => write!(f, "LMS signing failed"),
            Self::VerifyFailed => write!(f, "LMS verification failed"),
            Self::StateReadFailed => {
                write!(f, "LMS key state could not be read")
            }
        }
    }
}

impl Error for LmsError {}

pub fn default_seed() -> u64 {
    benchmark_seed_u64()
}

fn seed_material_from_u64(seed_value: u64) -> [u8; 32] {
    let mut rng = XorShift64::new(seed_value);
    let mut out = [0u8; 32];

    let mut offset = 0;
    while offset < out.len() {
        let chunk = rng.next_u64().to_le_bytes();
        let take = (out.len() - offset).min(chunk.len());
        out[offset..offset + take].copy_from_slice(&chunk[..take]);
        offset += take;
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

pq_bench::declare_peak_memory_api!();

#[cfg(test)]
mod tests {
    use super::{
        bench_message, param_set_by_name, LmsScheme, BENCH_MESSAGE_BYTE,
        DEFAULT_PARAM_SET_NAME,
    };

    fn run_with_large_stack(name: &str, test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .name(name.to_owned())
            .stack_size(32 * 1024 * 1024)
            .spawn(test)
            .expect("test thread should start")
            .join()
            .expect("test thread should complete");
    }

    #[test]
    fn param_set_lookup_works() {
        let found = param_set_by_name(DEFAULT_PARAM_SET_NAME)
            .expect("known param set should resolve");
        assert_eq!(found.name(), DEFAULT_PARAM_SET_NAME);
    }

    #[test]
    fn sign_verify_roundtrip() {
        run_with_large_stack("lms-roundtrip", || {
            let scheme = LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
                .expect("param set should resolve");
            let message = b"lms-roundtrip";
            let (public_key, mut secret_key) =
                scheme.keypair_with_seed(7).expect("keypair should succeed");

            let signature = scheme
                .sign(message, &mut secret_key)
                .expect("sign should succeed");
            let verified = scheme
                .verify(message, &signature, &public_key)
                .expect("verify should succeed");
            assert!(verified, "signature should verify");
        });
    }

    #[test]
    fn verify_fails_for_other_message() {
        run_with_large_stack("lms-verify-fail", || {
            let scheme = LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
                .expect("param set should resolve");
            let (public_key, mut secret_key) = scheme
                .keypair_with_seed(11)
                .expect("keypair should succeed");

            let signature = scheme
                .sign(b"message-a", &mut secret_key)
                .expect("sign should succeed");
            let verified = scheme
                .verify(b"message-b", &signature, &public_key)
                .expect("verify should succeed");
            assert!(!verified, "different message should fail verification");
        });
    }

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let msg = bench_message(16);
        assert_eq!(msg.len(), 16);
        assert!(msg.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }
}
