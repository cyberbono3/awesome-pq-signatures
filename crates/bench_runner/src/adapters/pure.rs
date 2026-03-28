use crate::registry::AdapterSpec;
use crate::types::{BenchRun, DsaBenchmark, SizeMetrics};

use super::shared::{measure_benchmark_flow, RunnerContext};

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

benchmark_adapter!(
    DilithiumAdapter,
    algorithm = "ML-DSA-65 (Dilithium)",
    param_set = "ML-DSA-65",
    run_once = |message| {
        use dilithium::{default_seed, ML_DSA_65};

        let seed = default_seed();
        Ok(measure_benchmark_flow(
            || ML_DSA_65.keypair(&seed),
            |keypair| ML_DSA_65.sign(keypair, message, &[]).expect("sign"),
            |keypair, signature| {
                let _ = ML_DSA_65.verify(keypair, message, &[], signature);
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
        use falcon::FALCON512;

        Ok(measure_benchmark_flow(
            || FALCON512.benchmark_keypair().expect("kg"),
            |keypair| FALCON512.sign_message(keypair, message).expect("sign"),
            |keypair, signature| {
                FALCON512
                    .verify_message(keypair, message, signature)
                    .expect("verify");
            },
            |keypair, signature| {
                let sizes = FALCON512.sizes(keypair, signature);
                SizeMetrics::new(
                    sizes.public_key,
                    sizes.secret_key,
                    sizes.signature,
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
        use sphincs_plus::SPHINCS_PLUS_SHAKE_128F_SIMPLE;

        Ok(measure_benchmark_flow(
            || {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE
                    .benchmark_keypair()
                    .expect("kg")
            },
            |keypair| {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE
                    .sign_message(keypair, message)
                    .expect("sign")
            },
            |keypair, signature| {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE
                    .verify_message(keypair, message, signature)
                    .expect("verify");
            },
            |keypair, signature| {
                let sizes =
                    SPHINCS_PLUS_SHAKE_128F_SIMPLE.sizes(keypair, signature);
                SizeMetrics::new(
                    sizes.public_key,
                    sizes.secret_key,
                    sizes.signature,
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

pub fn build_pure_adapter<T>(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark>
where
    T: DsaBenchmark + Default + 'static,
{
    Box::new(T::default())
}
