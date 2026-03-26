use pq_bench::{
    build_standard_binary_report, build_standard_human_benchmark_report,
    run_human_benchmark_binary, BenchmarkBinaryExecution, HumanBenchmarkLine,
    StandardBinaryBenchmarkSpec, StandardHumanBenchmarkSpec,
};
use xmssmt_bench::default_benchmark_scheme;

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let scheme = default_benchmark_scheme();
        let report = scheme
            .benchmark_report(message)
            .expect("xmssmt benchmark report must succeed");

        const BANNER: [&str; 4] = [
            "╔══════════════════════════════════════════════════╗",
            "║              XMSS^MT Benchmark                   ║",
            "║  NIST SP 800-208 Multi-Tree Signature Scheme     ║",
            "╚══════════════════════════════════════════════════╝",
        ];

        BenchmarkBinaryExecution {
            report: build_standard_binary_report(StandardBinaryBenchmarkSpec {
                algorithm: "XMSS^MT",
                backend: Some(scheme.backend_name()),
                param_set: Some(report.param_set.as_str()),
                keygen_duration: report.keygen_duration,
                sign_duration: report.sign_duration,
                verify_duration: report.verify_duration,
                verified: report.verified,
                public_key_bytes: report.public_key_size,
                secret_key_bytes: report.secret_key_size,
                signature_bytes: report.signature_size,
                signed_message_bytes: None,
                sign_peak_bytes: None,
                verify_peak_bytes: None,
            }),
            human: build_standard_human_benchmark_report(
                StandardHumanBenchmarkSpec {
                    banner_lines: &BANNER,
                    heading: report.display_name.clone().into(),
                    intro_lines: Vec::new(),
                    summary_algorithm: report.param_set.as_str().into(),
                    summary_intro_lines: Vec::new(),
                    keygen_duration: report.keygen_duration,
                    sign_duration: report.sign_duration,
                    verify_duration: report.verify_duration,
                    verified: report.verified,
                    size_lines: vec![
                        HumanBenchmarkLine::bytes(
                            "Public key size",
                            report.public_key_size,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Secret key size",
                            report.secret_key_size,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Signature size",
                            report.signature_size,
                        ),
                    ],
                    summary_size_lines: vec![
                        HumanBenchmarkLine::bytes(
                            "Public Key",
                            report.public_key_size,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Secret Key",
                            report.secret_key_size,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Signature",
                            report.signature_size,
                        ),
                    ],
                    sign_peak_bytes: None,
                    verify_peak_bytes: None,
                },
            ),
        }
    });
}
