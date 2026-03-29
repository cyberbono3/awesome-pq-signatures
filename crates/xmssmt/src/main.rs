use pq_bench::{
    build_standard_stateful_benchmark_execution, run_human_benchmark_binary,
    StandardStatefulBenchmarkExecutionSpec,
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

        build_standard_stateful_benchmark_execution(
            StandardStatefulBenchmarkExecutionSpec {
                banner_lines: &BANNER,
                heading: report.display_name.clone().into(),
                intro_lines: Vec::new(),
                algorithm: "XMSS^MT",
                backend: Some(scheme.backend_name()),
                param_set: Some(report.param_set.as_str()),
                summary_algorithm: report.param_set.as_str().into(),
                summary_intro_lines: Vec::new(),
                keygen_duration: report.keygen_duration,
                sign_duration: report.sign_duration,
                verify_duration: report.verify_duration,
                verified: report.verified,
                sizes: xmssmt_bench::XmssmtSizes {
                    public_key_bytes: report.public_key_size,
                    secret_key_bytes: report.secret_key_size,
                    signature_bytes: report.signature_size,
                },
                signed_message_bytes: None,
                extra_size_lines: Vec::new(),
            },
        )
    });
}
