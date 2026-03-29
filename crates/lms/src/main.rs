use lms::{
    default_seed, measure_time, signed_message_size, LmsScheme,
    DEFAULT_PARAM_SET_NAME,
};
use pq_bench::{
    build_standard_stateful_benchmark_execution, run_human_benchmark_binary,
    HumanBenchmarkLine, StandardStatefulBenchmarkExecutionSpec,
};
use std::env;

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let param_set_name = env::var("PARAM_SET")
            .unwrap_or_else(|_| DEFAULT_PARAM_SET_NAME.to_owned());
        let scheme = LmsScheme::from_param_set_name(&param_set_name)
            .expect("valid LMS parameter set");
        let seed = default_seed();

        let ((public_key, mut secret_key), keygen_duration) =
            measure_time(|| {
                scheme
                    .keypair_with_seed(seed)
                    .expect("LMS key generation should succeed")
            });
        let (signature, sign_duration) = measure_time(|| {
            scheme
                .sign(message, &mut secret_key)
                .expect("LMS signing should succeed")
        });
        let (verified, verify_duration) = measure_time(|| {
            scheme
                .verify(message, &signature, &public_key)
                .expect("LMS verify call should succeed")
        });

        let pk_size = scheme.public_key_size(&public_key);
        let sk_size = scheme.secret_key_size(&secret_key);
        let sig_size = scheme.signature_size(&signature);
        let remaining_signatures = scheme
            .remaining_signatures(&secret_key)
            .expect("LMS key state should be readable");

        build_standard_stateful_benchmark_execution(
            StandardStatefulBenchmarkExecutionSpec {
                banner_lines: &[],
                heading: format!("LMS ({})", scheme.param_set_name()).into(),
                intro_lines: vec![
                    HumanBenchmarkLine::new("Backend", scheme.backend_name()),
                    HumanBenchmarkLine::new(
                        "Tree height",
                        scheme.tree_height().to_string(),
                    ),
                ],
                algorithm: scheme.algorithm_name(),
                backend: Some(scheme.backend_name()),
                param_set: Some(scheme.param_set_name()),
                summary_algorithm: scheme.algorithm_name().into(),
                summary_intro_lines: vec![HumanBenchmarkLine::new(
                    "Param set",
                    scheme.param_set_name(),
                )],
                keygen_duration,
                sign_duration,
                verify_duration,
                verified,
                sizes: pq_bench::SignatureMaterialSizes {
                    public_key_bytes: pk_size,
                    secret_key_bytes: sk_size,
                    signature_bytes: sig_size,
                },
                signed_message_bytes: Some(signed_message_size(
                    message.len(),
                    sig_size,
                )),
                extra_size_lines: vec![HumanBenchmarkLine::new(
                    "Estimated signatures remaining",
                    remaining_signatures.to_string(),
                )],
            },
        )
    });
}
