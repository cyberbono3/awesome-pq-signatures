use crate::{
    benchmark_message, emit_benchmark_report, print_human_benchmark_report,
    BenchmarkBinaryConfig, BenchmarkBinaryReport, HumanBenchmarkReport,
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
