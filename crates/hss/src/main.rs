use hss::{
    default_seed, measure_time, signed_message_size, HssScheme, BENCH_MESSAGE,
    DEFAULT_PARAM_SET_NAME,
};
use pq_bench::{
    print_human_benchmark_report, HumanBenchmarkLine, HumanBenchmarkReport,
};
use std::env;

fn main() {
    let param_set_name = env::var("PARAM_SET")
        .unwrap_or_else(|_| DEFAULT_PARAM_SET_NAME.to_owned());
    let scheme = HssScheme::from_param_set_name(&param_set_name)
        .expect("valid HSS parameter set");
    let message: &[u8] = &BENCH_MESSAGE;
    let seed = default_seed();

    let ((public_key, mut secret_key), keygen_duration) = measure_time(|| {
        scheme
            .keypair_with_seed(seed)
            .expect("HSS key generation should succeed")
    });
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(&message, &mut secret_key)
            .expect("HSS signing should succeed")
    });
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify(&message, &signature, &public_key)
            .expect("HSS verify call should succeed")
    });

    let pk_size = scheme.public_key_size(&public_key);
    let sk_size = scheme.secret_key_size(&secret_key);
    let sig_size = scheme.signature_size(&signature);
    let key_lifetime = secret_key
        .lifetime()
        .expect("HSS key lifetime should be available");

    print_human_benchmark_report(&HumanBenchmarkReport {
        heading: format!("HSS ({})", scheme.param_set_name()).into(),
        intro_lines: vec![
            HumanBenchmarkLine::new("Backend", scheme.backend_name()),
            HumanBenchmarkLine::new(
                "Hierarchy levels",
                scheme.levels().to_string(),
            ),
        ],
        summary_algorithm: scheme.algorithm_name().into(),
        summary_intro_lines: vec![HumanBenchmarkLine::new(
            "Param set",
            scheme.param_set_name(),
        )],
        keygen_duration,
        sign_duration,
        verify_duration,
        verified,
        size_lines: vec![
            HumanBenchmarkLine::bytes("Public key size", pk_size),
            HumanBenchmarkLine::bytes("Secret key size", sk_size),
            HumanBenchmarkLine::bytes("Signature size", sig_size),
            HumanBenchmarkLine::bytes(
                "Signed message size",
                signed_message_size(message.len(), sig_size),
            ),
            HumanBenchmarkLine::new(
                "Estimated signatures per key",
                key_lifetime.to_string(),
            ),
        ],
        summary_size_lines: vec![
            HumanBenchmarkLine::bytes("Public Key", pk_size),
            HumanBenchmarkLine::bytes("Secret Key", sk_size),
            HumanBenchmarkLine::bytes("Signature", sig_size),
        ],
        ..HumanBenchmarkReport::default()
    });
}
