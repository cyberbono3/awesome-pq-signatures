use lamport_ots::{benchmark_once, LAMPORT_OTS_SCHEME};
use pq_bench::{
    benchmark_message, build_standard_binary_report, emit_benchmark_report,
    print_human_benchmark_report, signed_message_size, BenchmarkBinaryConfig,
    HumanBenchmarkLine, HumanBenchmarkReport, StandardBinaryBenchmarkSpec,
};

fn main() {
    let config = BenchmarkBinaryConfig::parse(std::env::args().skip(1))
        .unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        });
    let message = benchmark_message(config.message_size);
    let scheme = LAMPORT_OTS_SCHEME;
    let benchmark = benchmark_once(&message).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    let report = build_standard_binary_report(StandardBinaryBenchmarkSpec {
        algorithm: scheme.algorithm_name(),
        backend: Some(scheme.backend_name()),
        param_set: Some(scheme.param_set_name()),
        keygen_duration: benchmark.keygen_duration,
        sign_duration: benchmark.sign_duration,
        verify_duration: benchmark.verify_duration,
        verified: benchmark.verified,
        public_key_bytes: benchmark.sizes.public_key_bytes,
        secret_key_bytes: benchmark.sizes.secret_key_bytes,
        signature_bytes: benchmark.sizes.signature_bytes,
        signed_message_bytes: Some(signed_message_size(
            message.len(),
            benchmark.sizes.signature_bytes,
        )),
        sign_peak_bytes: None,
        verify_peak_bytes: None,
    });

    emit_benchmark_report(&config, &report, |_| {
        print_human_benchmark_report(&HumanBenchmarkReport {
            heading: format!(
                "{} ({})",
                scheme.algorithm_name(),
                scheme.param_set_name()
            )
            .into(),
            intro_lines: vec![HumanBenchmarkLine::new(
                "Backend",
                scheme.backend_name(),
            )],
            summary_algorithm: scheme.algorithm_name().into(),
            summary_intro_lines: vec![HumanBenchmarkLine::new(
                "Param set",
                scheme.param_set_name(),
            )],
            keygen_duration: benchmark.keygen_duration,
            sign_duration: benchmark.sign_duration,
            verify_duration: benchmark.verify_duration,
            verified: benchmark.verified,
            size_lines: vec![
                HumanBenchmarkLine::bytes(
                    "Public key size",
                    benchmark.sizes.public_key_bytes,
                ),
                HumanBenchmarkLine::bytes(
                    "Secret key size",
                    benchmark.sizes.secret_key_bytes,
                ),
                HumanBenchmarkLine::bytes(
                    "Signature size",
                    benchmark.sizes.signature_bytes,
                ),
                HumanBenchmarkLine::bytes(
                    "Signed message size",
                    signed_message_size(
                        message.len(),
                        benchmark.sizes.signature_bytes,
                    ),
                ),
                HumanBenchmarkLine::new(
                    "Max signatures per key",
                    scheme.max_signatures_per_key().to_string(),
                ),
            ],
            summary_size_lines: vec![
                HumanBenchmarkLine::bytes(
                    "Public Key",
                    benchmark.sizes.public_key_bytes,
                ),
                HumanBenchmarkLine::bytes(
                    "Secret Key",
                    benchmark.sizes.secret_key_bytes,
                ),
                HumanBenchmarkLine::bytes(
                    "Signature",
                    benchmark.sizes.signature_bytes,
                ),
            ],
            ..HumanBenchmarkReport::default()
        });
    });
}
