use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use pq_bench::{measure_time, BenchmarkBinaryReport};

use crate::registry::AdapterSpec;
use crate::types::{BenchRun, DsaBenchmark, SizeMetrics};

pub struct RunnerContext {
    pub message_size: usize,
    pub binary_executables: HashMap<&'static str, PathBuf>,
}

macro_rules! benchmark_adapter {
    (
        $name:ident,
        algorithm = $algorithm:literal,
        param_set = $param_set:literal,
        run_once = |$message:ident| $body:block
    ) => {
        #[derive(Default)]
        pub struct $name;

        impl DsaBenchmark for $name {
            fn name(&self) -> &str {
                $algorithm
            }

            fn param_set(&self) -> &str {
                $param_set
            }

            fn run_once(&self, $message: &[u8]) -> Result<BenchRun, String> {
                $body
            }
        }
    };
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

benchmark_adapter!(
    DilithiumAdapter,
    algorithm = "ML-DSA-65 (Dilithium)",
    param_set = "ML-DSA-65",
    run_once = |message| {
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
);

benchmark_adapter!(
    FalconAdapter,
    algorithm = "Falcon-512",
    param_set = "Falcon-512",
    run_once = |message| {
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
);

benchmark_adapter!(
    SphincsPlusAdapter,
    algorithm = "SPHINCS+-SHAKE-128f",
    param_set = "SPHINCS+-SHAKE-128f-simple",
    run_once = |message| {
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
);

benchmark_adapter!(
    MayoAdapter,
    algorithm = "MAYO-1",
    param_set = "MAYO-1",
    run_once = |message| {
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
);

benchmark_adapter!(
    LamportAdapter,
    algorithm = "Lamport OTS",
    param_set = "Lamport-OTS-256",
    run_once = |message| {
        use lamport_ots::LAMPORT_OTS_SCHEME;

        Ok(measure_benchmark_flow(
            || {
                LAMPORT_OTS_SCHEME.keypair_with_seed(
                    lamport_ots::seed_from_str("bench-runner-lamport"),
                )
            },
            |(_, secret_key)| {
                LAMPORT_OTS_SCHEME.sign(message, secret_key).expect("sign")
            },
            |(public_key, _), signature| {
                LAMPORT_OTS_SCHEME
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |_, _| {
                let sizes = LAMPORT_OTS_SCHEME.sizes();
                SizeMetrics::new(
                    sizes.public_key_bytes,
                    sizes.secret_key_bytes,
                    sizes.signature_bytes,
                )
            },
        ))
    }
);

benchmark_adapter!(
    LmsAdapter,
    algorithm = "LMS",
    param_set = "LMS-SHA256-M32-H5",
    run_once = |message| {
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
);

benchmark_adapter!(
    HssAdapter,
    algorithm = "HSS",
    param_set = "HSS-SHA256-H5-W2-L1",
    run_once = |message| {
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
);

benchmark_adapter!(
    XmssAdapter,
    algorithm = "XMSS",
    param_set = "XMSS-SHA2_10_256",
    run_once = |message| {
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
);

benchmark_adapter!(
    XmssmtAdapter,
    algorithm = "XMSS^MT",
    param_set = "XMSSMT-SHA2_20/2_256",
    run_once = |message| {
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
);

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

pub fn build_pure_adapter<T>(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark>
where
    T: DsaBenchmark + Default + 'static,
{
    Box::new(T::default())
}

pub fn build_binary_adapter(
    context: &RunnerContext,
    spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(SubprocessAdapter {
        algorithm: spec.algorithm,
        param_set: spec.param_set,
        executable: context
            .binary_executables
            .get(spec.algorithm)
            .expect("binary executable should be resolved")
            .clone(),
        message_size: context.message_size,
    })
}
