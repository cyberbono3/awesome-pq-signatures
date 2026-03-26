use crate::{
    benchmark_message, build_standard_binary_report, emit_benchmark_report,
    emit_standard_benchmark_report, measure_time, print_human_benchmark_report,
    signed_message_size, BenchmarkBinaryConfig, BenchmarkBinaryReport,
    HumanBenchmarkReport, StandardBenchmarkHumanReport,
    StandardBinaryBenchmarkSpec,
};

pub struct BenchmarkBinaryExecution<'a> {
    pub report: BenchmarkBinaryReport,
    pub human: HumanBenchmarkReport<'a>,
}

pub fn parse_benchmark_binary_config_or_exit(
    args: impl IntoIterator<Item = String>,
) -> BenchmarkBinaryConfig {
    BenchmarkBinaryConfig::parse(args).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    })
}

pub fn run_human_benchmark_binary<'a>(
    args: impl IntoIterator<Item = String>,
    build: impl FnOnce(&[u8]) -> BenchmarkBinaryExecution<'a>,
) {
    let config = parse_benchmark_binary_config_or_exit(args);
    let message = benchmark_message(config.message_size);
    let execution = build(&message);
    emit_benchmark_report(&config, &execution.report, |_| {
        print_human_benchmark_report(&execution.human);
    });
}

pub struct StandardSignedMessageBinaryLabels<'a> {
    pub algorithm: &'a str,
    pub param_set: &'a str,
    pub heading_algorithm: &'a str,
    pub heading_param_set: &'a str,
    pub summary_algorithm: &'a str,
    pub backend: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardBenchmarkSizes {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

pub fn run_standard_signed_message_benchmark_binary<K, S>(
    args: impl IntoIterator<Item = String>,
    labels: StandardSignedMessageBinaryLabels<'_>,
    keygen: impl FnOnce() -> K,
    sign: impl FnOnce(&K, &[u8]) -> S,
    verify: impl FnOnce(&K, &[u8], &S) -> bool,
    sizes: impl FnOnce(&K, &S) -> StandardBenchmarkSizes,
    reset_peak: impl Fn(),
    peak_bytes: impl Fn() -> usize,
) {
    let config = parse_benchmark_binary_config_or_exit(args);
    let message = benchmark_message(config.message_size);
    let (keypair, keygen_duration) = measure_time(keygen);
    reset_peak();
    let (signature, sign_duration) = measure_time(|| sign(&keypair, &message));
    let sign_peak_bytes = peak_bytes();
    reset_peak();
    let (verified, verify_duration) =
        measure_time(|| verify(&keypair, &message, &signature));
    let verify_peak_bytes = peak_bytes();
    let sizes = sizes(&keypair, &signature);

    let report = build_standard_binary_report(StandardBinaryBenchmarkSpec {
        algorithm: labels.algorithm,
        backend: labels.backend,
        param_set: Some(labels.param_set),
        keygen_duration,
        sign_duration,
        verify_duration,
        verified,
        public_key_bytes: sizes.public_key_bytes,
        secret_key_bytes: sizes.secret_key_bytes,
        signature_bytes: sizes.signature_bytes,
        signed_message_bytes: Some(signed_message_size(
            message.len(),
            sizes.signature_bytes,
        )),
        sign_peak_bytes: Some(sign_peak_bytes),
        verify_peak_bytes: Some(verify_peak_bytes),
    });

    emit_standard_benchmark_report(
        &config,
        &report,
        StandardBenchmarkHumanReport {
            heading_algorithm: labels.heading_algorithm,
            heading_param_set: labels.heading_param_set,
            summary_algorithm: labels.summary_algorithm,
            keygen_duration,
            sign_duration,
            verify_duration,
            public_key_bytes: sizes.public_key_bytes,
            secret_key_bytes: sizes.secret_key_bytes,
            signature_bytes: sizes.signature_bytes,
            sign_peak_bytes,
            verify_peak_bytes,
        },
    );
}
