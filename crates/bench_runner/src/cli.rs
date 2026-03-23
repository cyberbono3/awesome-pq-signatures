use std::path::PathBuf;

use pq_bench::BENCH_MESSAGE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliConfig {
    pub runs: usize,
    pub output: PathBuf,
    pub only_filters: Vec<String>,
    pub param_set_filters: Vec<String>,
    pub skip_ffi: bool,
    pub message_size: usize,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            runs: 10,
            output: PathBuf::from("benchmarks/results.csv"),
            only_filters: Vec::new(),
            param_set_filters: Vec::new(),
            skip_ffi: false,
            message_size: BENCH_MESSAGE.len(),
        }
    }
}

#[derive(Debug)]
pub enum CliAction {
    Help,
    Run(CliConfig),
}

impl CliAction {
    pub fn parse(
        args: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let mut config = CliConfig::default();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--runs" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--runs requires a value".to_string())?;
                    config.runs = value
                        .parse()
                        .map_err(|_| format!("invalid runs value: {value}"))?;
                    if config.runs == 0 {
                        return Err("--runs must be greater than 0".to_string());
                    }
                }
                "--output" => {
                    let value = args.next().ok_or_else(|| {
                        "--output requires a value".to_string()
                    })?;
                    config.output = PathBuf::from(value);
                }
                "--only" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--only requires a value".to_string())?;
                    config.only_filters.push(value.to_ascii_lowercase());
                }
                "--param-set" => {
                    let value = args.next().ok_or_else(|| {
                        "--param-set requires a value".to_string()
                    })?;
                    config.param_set_filters.push(value.to_ascii_lowercase());
                }
                "--skip-ffi" => config.skip_ffi = true,
                "--message-size" => {
                    let value = args.next().ok_or_else(|| {
                        "--message-size requires a value".to_string()
                    })?;
                    config.message_size = value.parse().map_err(|_| {
                        format!("invalid message size: {value}")
                    })?;
                    if config.message_size == 0 {
                        return Err(
                            "--message-size must be greater than 0".to_string()
                        );
                    }
                }
                "--help" | "-h" => return Ok(Self::Help),
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        Ok(Self::Run(config))
    }
}

pub fn print_help() {
    println!("Usage: bench_runner [options]");
    println!(
        "  --runs N              Number of benchmark samples per algorithm"
    );
    println!("  --output PATH         CSV output path");
    println!(
        "  --only TEXT           Filter algorithms by substring (repeatable)"
    );
    println!(
        "  --param-set TEXT      Filter param sets by substring (repeatable)"
    );
    println!("  --skip-ffi            Skip subprocess-based FFI algorithms");
    println!("  --message-size N      Benchmark message size in bytes");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_action_parses_filters_and_message_size() {
        let action = CliAction::parse([
            "--runs".to_string(),
            "7".to_string(),
            "--only".to_string(),
            "xmss".to_string(),
            "--param-set".to_string(),
            "sha2".to_string(),
            "--message-size".to_string(),
            "256".to_string(),
        ])
        .expect("config should parse");

        match action {
            CliAction::Run(config) => {
                assert_eq!(config.runs, 7);
                assert_eq!(config.only_filters, vec!["xmss"]);
                assert_eq!(config.param_set_filters, vec!["sha2"]);
                assert_eq!(config.message_size, 256);
            }
            CliAction::Help => panic!("expected run config"),
        }
    }

    #[test]
    fn cli_action_rejects_zero_message_size() {
        let err =
            CliAction::parse(["--message-size".to_string(), "0".to_string()])
                .expect_err("zero message size should fail");
        assert_eq!(err, "--message-size must be greater than 0");
    }
}
