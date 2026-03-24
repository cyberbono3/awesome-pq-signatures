use pq_bench::{
    print_human_benchmark_report, HumanBenchmarkLine, HumanBenchmarkReport,
};
use xmss_bench::{default_benchmark_scheme, BENCH_MESSAGE};

const MESSAGE: &[u8] = &BENCH_MESSAGE;

fn main() {
    let scheme = default_benchmark_scheme();
    let report = scheme
        .benchmark_report(MESSAGE)
        .expect("xmss benchmark report must succeed");

    const BANNER: [&str; 4] = [
        "╔══════════════════════════════════════════════════╗",
        "║              XMSS Benchmark                      ║",
        "║  NIST SP 800-208 Hash-Based Signature Scheme    ║",
        "╚══════════════════════════════════════════════════╝",
    ];

    print_human_benchmark_report(&HumanBenchmarkReport {
        banner_lines: &BANNER,
        heading: report.display_name.as_str().into(),
        summary_algorithm: report.param_set.as_str().into(),
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
            HumanBenchmarkLine::bytes("Signature size", report.signature_size),
        ],
        summary_size_lines: vec![
            HumanBenchmarkLine::bytes("Public Key", report.public_key_size),
            HumanBenchmarkLine::bytes("Secret Key", report.secret_key_size),
            HumanBenchmarkLine::bytes("Signature", report.signature_size),
        ],
        ..HumanBenchmarkReport::default()
    });
}
