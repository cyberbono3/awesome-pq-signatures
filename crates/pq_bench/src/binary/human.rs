use crate::{
    benchmark_message, build_standard_binary_report,
    build_standard_human_benchmark_report, emit_benchmark_report,
    print_human_benchmark_report, HumanBenchmarkLine, HumanBenchmarkReport,
    StandardBinaryBenchmarkSpec, StandardHumanBenchmarkSpec,
};
use std::{borrow::Cow, time::Duration};

use super::config::parse_benchmark_binary_config_or_exit;

pub struct BenchmarkBinaryExecution<'a> {
    pub report: crate::BenchmarkBinaryReport,
    pub human: HumanBenchmarkReport<'a>,
}

pub struct StandardBenchmarkExecutionSpec<'a> {
    pub banner_lines: &'a [&'a str],
    pub heading: Cow<'a, str>,
    pub intro_lines: Vec<HumanBenchmarkLine<'a>>,
    pub algorithm: &'a str,
    pub backend: Option<&'a str>,
    pub param_set: Option<&'a str>,
    pub summary_algorithm: Cow<'a, str>,
    pub summary_intro_lines: Vec<HumanBenchmarkLine<'a>>,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub verified: bool,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
    pub signed_message_bytes: Option<usize>,
    pub size_lines: Vec<HumanBenchmarkLine<'a>>,
    pub summary_size_lines: Vec<HumanBenchmarkLine<'a>>,
    pub sign_peak_bytes: Option<usize>,
    pub verify_peak_bytes: Option<usize>,
}

pub fn build_standard_benchmark_execution<'a>(
    spec: StandardBenchmarkExecutionSpec<'a>,
) -> BenchmarkBinaryExecution<'a> {
    BenchmarkBinaryExecution {
        report: build_standard_binary_report(StandardBinaryBenchmarkSpec {
            algorithm: spec.algorithm,
            backend: spec.backend,
            param_set: spec.param_set,
            keygen_duration: spec.keygen_duration,
            sign_duration: spec.sign_duration,
            verify_duration: spec.verify_duration,
            verified: spec.verified,
            public_key_bytes: spec.public_key_bytes,
            secret_key_bytes: spec.secret_key_bytes,
            signature_bytes: spec.signature_bytes,
            signed_message_bytes: spec.signed_message_bytes,
            sign_peak_bytes: spec.sign_peak_bytes,
            verify_peak_bytes: spec.verify_peak_bytes,
        }),
        human: build_standard_human_benchmark_report(
            StandardHumanBenchmarkSpec {
                banner_lines: spec.banner_lines,
                heading: spec.heading,
                intro_lines: spec.intro_lines,
                summary_algorithm: spec.summary_algorithm,
                summary_intro_lines: spec.summary_intro_lines,
                keygen_duration: spec.keygen_duration,
                sign_duration: spec.sign_duration,
                verify_duration: spec.verify_duration,
                verified: spec.verified,
                size_lines: spec.size_lines,
                summary_size_lines: spec.summary_size_lines,
                sign_peak_bytes: spec.sign_peak_bytes,
                verify_peak_bytes: spec.verify_peak_bytes,
            },
        ),
    }
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
