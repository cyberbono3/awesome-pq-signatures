use crate::message::BENCH_MESSAGE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkOutputFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkBinaryConfig {
    pub output_format: BenchmarkOutputFormat,
    pub message_size: usize,
}

impl Default for BenchmarkBinaryConfig {
    fn default() -> Self {
        Self {
            output_format: BenchmarkOutputFormat::Human,
            message_size: BENCH_MESSAGE.len(),
        }
    }
}

impl BenchmarkBinaryConfig {
    pub fn parse(
        args: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--format" => {
                    let value = args.next().ok_or_else(|| {
                        "--format requires a value".to_string()
                    })?;
                    config.output_format = match value.as_str() {
                        "human" => BenchmarkOutputFormat::Human,
                        "json" => BenchmarkOutputFormat::Json,
                        _ => {
                            return Err(format!(
                                "unsupported format: {value} (expected human or json)"
                            ))
                        }
                    };
                }
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
                "--help" | "-h" => {
                    return Err(
                        "usage: [--format human|json] [--message-size N]"
                            .to_string(),
                    )
                }
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        Ok(config)
    }
}
