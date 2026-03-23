use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use pq_bench::{measure_time, BenchmarkBinaryReport};

use crate::registry::AdapterSpec;
use crate::types::{BenchRun, DsaBenchmark, SizeMetrics};

pub struct RunnerContext {
    pub message_size: usize,
    pub ffi_executables: HashMap<&'static str, PathBuf>,
}

fn measure_benchmark_flow<K, S>(
    keygen: impl FnOnce() -> K,
    sign: impl FnOnce(&mut K) -> S,
    verify: impl FnOnce(&K, &S),
    sizes: impl FnOnce(&K, &S) -> SizeMetrics,
) -> BenchRun {
    let (mut key_material, keygen_duration) = measure_time(keygen);
    let (signature, sign_duration) = measure_time(|| sign(&mut key_material));
    let (_, verify_duration) =
        measure_time(|| verify(&key_material, &signature));
    BenchRun::from_durations(
        keygen_duration,
        sign_duration,
        verify_duration,
        sizes(&key_material, &signature),
    )
}

pub struct DilithiumAdapter;

impl DsaBenchmark for DilithiumAdapter {
    fn name(&self) -> &str {
        "ML-DSA-65 (Dilithium)"
    }

    fn param_set(&self) -> &str {
        "ML-DSA-65"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use dilithium::{default_seed, SignatureScheme as _, ML_DSA_65};

        let seed = default_seed();
        Ok(measure_benchmark_flow(
            || ML_DSA_65.keypair(&seed),
            |keypair| ML_DSA_65.sign(keypair, message, &[]).expect("sign"),
            |keypair, signature| {
                ML_DSA_65.verify(keypair, message, &[], signature);
            },
            |keypair, signature| {
                SizeMetrics::new(
                    ML_DSA_65.public_key_size(keypair),
                    ML_DSA_65.secret_key_size(keypair),
                    ML_DSA_65.signature_size(signature),
                )
            },
        ))
    }
}

pub struct FalconAdapter;

impl DsaBenchmark for FalconAdapter {
    fn name(&self) -> &str {
        "Falcon-512"
    }

    fn param_set(&self) -> &str {
        "Falcon-512"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use falcon::{signature_size, SignatureScheme as _, FALCON512};
        use pqcrypto_traits::sign::{PublicKey, SecretKey};

        Ok(measure_benchmark_flow(
            || FALCON512.keypair(),
            |(_, secret_key)| FALCON512.sign(message, secret_key),
            |(public_key, _), signed_message| {
                FALCON512.open(signed_message, public_key);
            },
            |(public_key, secret_key), signed_message| {
                SizeMetrics::new(
                    public_key.as_bytes().len(),
                    secret_key.as_bytes().len(),
                    signature_size(signed_message, message.len()),
                )
            },
        ))
    }
}

pub struct SphincsPlusAdapter;

impl DsaBenchmark for SphincsPlusAdapter {
    fn name(&self) -> &str {
        "SPHINCS+-SHAKE-128f"
    }

    fn param_set(&self) -> &str {
        "SPHINCS+-SHAKE-128f-simple"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use pqcrypto_traits::sign::{PublicKey, SecretKey};
        use sphincs_plus::{
            signature_size, SignatureScheme as _,
            SPHINCS_PLUS_SHAKE_128F_SIMPLE,
        };

        Ok(measure_benchmark_flow(
            || SPHINCS_PLUS_SHAKE_128F_SIMPLE.keypair(),
            |(_, secret_key)| {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE.sign(message, secret_key)
            },
            |(public_key, _), signed_message| {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE.open(signed_message, public_key);
            },
            |(public_key, secret_key), signed_message| {
                SizeMetrics::new(
                    public_key.as_bytes().len(),
                    secret_key.as_bytes().len(),
                    signature_size(signed_message, message.len()),
                )
            },
        ))
    }
}

pub struct MayoAdapter;

impl DsaBenchmark for MayoAdapter {
    fn name(&self) -> &str {
        "MAYO-1"
    }

    fn param_set(&self) -> &str {
        "MAYO-1"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use mayo::MAYO;

        Ok(measure_benchmark_flow(
            || MAYO.benchmark_keypair(),
            |keypair| MAYO.sign_message(keypair, message).expect("sign"),
            |keypair, signature| {
                MAYO.verify_message(keypair, message, signature);
            },
            |keypair, signature| {
                let sizes = MAYO.sizes(keypair, signature);
                SizeMetrics::new(
                    sizes.public_key_bytes,
                    sizes.secret_key_bytes,
                    sizes.signature_bytes,
                )
            },
        ))
    }
}

pub struct LmsAdapter;

impl DsaBenchmark for LmsAdapter {
    fn name(&self) -> &str {
        "LMS"
    }

    fn param_set(&self) -> &str {
        "LMS-SHA256-M32-H5"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use lms::{default_seed, LmsScheme, DEFAULT_PARAM_SET_NAME};

        let scheme = LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .map_err(|err| format!("{err:?}"))?;
        Ok(measure_benchmark_flow(
            || scheme.keypair_with_seed(default_seed()).expect("kg"),
            |(_, secret_key)| scheme.sign(message, secret_key).expect("sign"),
            |(public_key, _), signature| {
                scheme
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    scheme.public_key_size(public_key),
                    scheme.secret_key_size(secret_key),
                    scheme.signature_size(signature),
                )
            },
        ))
    }
}

pub struct HssAdapter;

impl DsaBenchmark for HssAdapter {
    fn name(&self) -> &str {
        "HSS"
    }

    fn param_set(&self) -> &str {
        "HSS-SHA256-H5-W2-L1"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use hss::{default_seed, HssScheme, DEFAULT_PARAM_SET_NAME};

        let scheme = HssScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .map_err(|err| format!("{err:?}"))?;
        Ok(measure_benchmark_flow(
            || scheme.keypair_with_seed(default_seed()).expect("kg"),
            |(_, secret_key)| scheme.sign(message, secret_key).expect("sign"),
            |(public_key, _), signature| {
                scheme
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    scheme.public_key_size(public_key),
                    scheme.secret_key_size(secret_key),
                    scheme.signature_size(signature),
                )
            },
        ))
    }
}

pub struct XmssAdapter;

impl DsaBenchmark for XmssAdapter {
    fn name(&self) -> &str {
        "XMSS"
    }

    fn param_set(&self) -> &str {
        "XMSS-SHA2_10_256"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        let scheme = xmss_bench::default_benchmark_scheme();
        Ok(measure_benchmark_flow(
            || scheme.keypair().expect("kg"),
            |(_, secret_key)| scheme.sign(message, secret_key).expect("sign"),
            |(public_key, _), signature| {
                scheme
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    public_key.len(),
                    secret_key.len(),
                    signature.len(),
                )
            },
        ))
    }
}

pub struct XmssmtAdapter;

impl DsaBenchmark for XmssmtAdapter {
    fn name(&self) -> &str {
        "XMSS^MT"
    }

    fn param_set(&self) -> &str {
        "XMSSMT-SHA2_20/2_256"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        let scheme = xmssmt_bench::default_benchmark_scheme();
        Ok(measure_benchmark_flow(
            || {
                let mut keypair = scheme.keypair().expect("kg");
                let sizes = SizeMetrics::new(
                    keypair.public_key_len(),
                    keypair.secret_key_len(),
                    0,
                );
                (keypair, sizes)
            },
            |(keypair, _)| keypair.sign(message).expect("sign"),
            |(keypair, _), signature| {
                keypair.verify(message, signature).expect("verify");
            },
            |(_, sizes), signature| {
                SizeMetrics::new(
                    sizes.public_key_bytes,
                    sizes.secret_key_bytes,
                    signature.len(),
                )
            },
        ))
    }
}

pub struct LeansigAdapter;

impl DsaBenchmark for LeansigAdapter {
    fn name(&self) -> &str {
        "LeanSig"
    }

    fn param_set(&self) -> &str {
        "Poseidon-L2^18-TS-w4"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use leansig::serialization::Serializable;
        use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4NoOff;
        use leansig::signature::SignatureScheme;
        use leansig::MESSAGE_LENGTH;
        use leansig_bench::prepare_sk_for_epoch;

        type Scheme = SIGTargetSumLifetime18W4NoOff;

        let message = copy_into_fixed::<MESSAGE_LENGTH>(message);
        let mut rng = rand::rng();
        Ok(measure_benchmark_flow(
            || Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize),
            |(_, secret_key)| {
                prepare_sk_for_epoch(secret_key, 1);
                Scheme::sign(secret_key, 1, &message).expect("sign")
            },
            |(public_key, _), signature| {
                Scheme::verify(public_key, 1, &message, signature);
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    public_key.to_bytes().len(),
                    secret_key.to_bytes().len(),
                    signature.to_bytes().len(),
                )
            },
        ))
    }
}

pub struct SubprocessAdapter {
    pub algorithm: &'static str,
    pub param_set: &'static str,
    pub executable: PathBuf,
    pub message_size: usize,
}

impl DsaBenchmark for SubprocessAdapter {
    fn name(&self) -> &str {
        self.algorithm
    }

    fn param_set(&self) -> &str {
        self.param_set
    }

    fn run_once(&self, _message: &[u8]) -> Result<BenchRun, String> {
        let output = Command::new(&self.executable)
            .args([
                "--format",
                "json",
                "--message-size",
                &self.message_size.to_string(),
            ])
            .output()
            .map_err(|err| {
                format!(
                    "failed to execute {}: {err}",
                    self.executable.display()
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "exit {}: {}",
                output.status,
                stderr.lines().last().unwrap_or("")
            ));
        }

        let report: BenchmarkBinaryReport =
            serde_json::from_slice(&output.stdout)
                .map_err(|err| format!("invalid benchmark JSON: {err}"))?;

        Ok(BenchRun::from_binary_report(&report))
    }
}

pub fn build_dilithium(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(DilithiumAdapter)
}

pub fn build_falcon(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(FalconAdapter)
}

pub fn build_sphincs_plus(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(SphincsPlusAdapter)
}

pub fn build_mayo(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(MayoAdapter)
}

pub fn build_lms(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(LmsAdapter)
}

pub fn build_hss(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(HssAdapter)
}

pub fn build_xmss(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(XmssAdapter)
}

pub fn build_xmssmt(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(XmssmtAdapter)
}

pub fn build_leansig(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(LeansigAdapter)
}

pub fn build_ffi_adapter(
    context: &RunnerContext,
    spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(SubprocessAdapter {
        algorithm: spec.algorithm,
        param_set: spec.param_set,
        executable: context
            .ffi_executables
            .get(spec.algorithm)
            .expect("ffi executable should be resolved")
            .clone(),
        message_size: context.message_size,
    })
}

fn copy_into_fixed<const N: usize>(message: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let len = message.len().min(N);
    output[..len].copy_from_slice(&message[..len]);
    output
}
