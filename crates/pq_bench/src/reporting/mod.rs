mod binary;
mod human;

pub use binary::{
    build_standard_binary_report, emit_benchmark_report, BenchmarkBinaryReport,
    BenchmarkSizeReport, StandardBinaryBenchmarkSpec,
};
pub use human::{
    build_standard_human_benchmark_report, emit_standard_benchmark_report,
    print_human_benchmark_report, HumanBenchmarkLine, HumanBenchmarkReport,
    HumanBenchmarkSection, StandardBenchmarkHumanReport,
    StandardHumanBenchmarkSpec,
};
