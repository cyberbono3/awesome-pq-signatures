use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4NoOff;
use leansig_bench::benchmark_once;
use pq_bench::{
    build_standard_binary_report, build_standard_human_benchmark_report,
    run_human_benchmark_binary, BenchmarkBinaryExecution,
    HumanBenchmarkLine, StandardBinaryBenchmarkSpec,
    StandardHumanBenchmarkSpec,
};

const ALGORITHM: &str = "LeanSig";
const BACKEND: &str = "leanEthereum/leanSig";
const PARAM_SET: &str = "Poseidon-L2^18-TS-w4";
const DISPLAY_NAME: &str = "LeanSig Poseidon - L 2^18 - Target Sum - w 4";
const BANNER: [&str; 4] = [
    "╔══════════════════════════════════════════════════╗",
    "║          LeanSig Benchmark                       ║",
    "║  Poseidon2-based XMSS with Target Sum Encoding  ║",
    "╚══════════════════════════════════════════════════╝",
];

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let benchmark =
            benchmark_once::<SIGTargetSumLifetime18W4NoOff>(message)
                .unwrap_or_else(|err| {
                    eprintln!("{err}");
                    std::process::exit(1);
                });

        BenchmarkBinaryExecution {
            report: build_standard_binary_report(StandardBinaryBenchmarkSpec {
                algorithm: ALGORITHM,
                backend: Some(BACKEND),
                param_set: Some(PARAM_SET),
                keygen_duration: benchmark.keygen_duration,
                sign_duration: benchmark.sign_duration,
                verify_duration: benchmark.verify_duration,
                verified: benchmark.verified,
                public_key_bytes: benchmark.public_key_bytes,
                secret_key_bytes: benchmark.secret_key_bytes,
                signature_bytes: benchmark.signature_bytes,
                signed_message_bytes: None,
                sign_peak_bytes: None,
                verify_peak_bytes: None,
            }),
            human: build_standard_human_benchmark_report(
                StandardHumanBenchmarkSpec {
                    banner_lines: &BANNER,
                    heading: DISPLAY_NAME.into(),
                    intro_lines: vec![HumanBenchmarkLine::new(
                        "Backend", BACKEND,
                    )],
                    summary_algorithm: ALGORITHM.into(),
                    summary_intro_lines: vec![
                        HumanBenchmarkLine::new("Backend", BACKEND),
                        HumanBenchmarkLine::new("Param set", PARAM_SET),
                    ],
                    keygen_duration: benchmark.keygen_duration,
                    sign_duration: benchmark.sign_duration,
                    verify_duration: benchmark.verify_duration,
                    verified: benchmark.verified,
                    size_lines: vec![
                        HumanBenchmarkLine::bytes(
                            "Public key size",
                            benchmark.public_key_bytes,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Secret key size",
                            benchmark.secret_key_bytes,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Signature size",
                            benchmark.signature_bytes,
                        ),
                    ],
                    summary_size_lines: vec![
                        HumanBenchmarkLine::bytes(
                            "Public Key",
                            benchmark.public_key_bytes,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Secret Key",
                            benchmark.secret_key_bytes,
                        ),
                        HumanBenchmarkLine::bytes(
                            "Signature",
                            benchmark.signature_bytes,
                        ),
                    ],
                    sign_peak_bytes: None,
                    verify_peak_bytes: None,
                },
            ),
        }
    });
}
