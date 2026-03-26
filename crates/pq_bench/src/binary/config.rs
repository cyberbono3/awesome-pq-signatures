use crate::BenchmarkBinaryConfig;

pub fn parse_benchmark_binary_config_or_exit(
    args: impl IntoIterator<Item = String>,
) -> BenchmarkBinaryConfig {
    BenchmarkBinaryConfig::parse(args).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    })
}
