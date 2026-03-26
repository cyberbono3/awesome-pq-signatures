use lamport_ots::{benchmark_once, LAMPORT_OTS_SCHEME};
use pq_bench::{
    build_standard_binary_report, build_standard_human_benchmark_report,
    run_human_benchmark_binary, signed_message_size, BenchmarkBinaryExecution,
    HumanBenchmarkLine, StandardBinaryBenchmarkSpec,
    StandardHumanBenchmarkSpec,
};

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let scheme = LAMPORT_OTS_SCHEME;
        let benchmark = benchmark_once(message).unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        });

        BenchmarkBinaryExecution {
            report: build_standard_binary_report(StandardBinaryBenchmarkSpec {
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
            }),
            human: build_standard_human_benchmark_report(
                StandardHumanBenchmarkSpec {
                    banner_lines: &[],
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
                    sign_peak_bytes: None,
                    verify_peak_bytes: None,
                },
            ),
        }
    });
}
