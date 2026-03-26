use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{duration_ns, BenchmarkBinaryConfig, BenchmarkOutputFormat};

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct BenchmarkSizeReport {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message_bytes: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkBinaryReport {
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_set: Option<String>,
    pub keygen_ns: u64,
    pub sign_ns: u64,
    pub verify_ns: u64,
    pub verified: bool,
    pub sizes: BenchmarkSizeReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_peak_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_peak_bytes: Option<usize>,
}

pub struct StandardBinaryBenchmarkSpec<'a> {
    pub algorithm: &'a str,
    pub backend: Option<&'a str>,
    pub param_set: Option<&'a str>,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub verified: bool,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
    pub signed_message_bytes: Option<usize>,
    pub sign_peak_bytes: Option<usize>,
    pub verify_peak_bytes: Option<usize>,
}

pub fn build_standard_binary_report(
    spec: StandardBinaryBenchmarkSpec<'_>,
) -> BenchmarkBinaryReport {
    BenchmarkBinaryReport {
        algorithm: spec.algorithm.to_string(),
        backend: spec.backend.map(str::to_string),
        param_set: spec.param_set.map(str::to_string),
        keygen_ns: duration_ns(spec.keygen_duration),
        sign_ns: duration_ns(spec.sign_duration),
        verify_ns: duration_ns(spec.verify_duration),
        verified: spec.verified,
        sizes: BenchmarkSizeReport {
            public_key_bytes: spec.public_key_bytes,
            secret_key_bytes: spec.secret_key_bytes,
            signature_bytes: spec.signature_bytes,
            signed_message_bytes: spec.signed_message_bytes,
        },
        sign_peak_bytes: spec.sign_peak_bytes,
        verify_peak_bytes: spec.verify_peak_bytes,
    }
}

pub fn emit_benchmark_report(
    config: &BenchmarkBinaryConfig,
    report: &BenchmarkBinaryReport,
    render_human: impl FnOnce(&BenchmarkBinaryReport),
) {
    match config.output_format {
        BenchmarkOutputFormat::Human => render_human(report),
        BenchmarkOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(report)
                    .expect("benchmark report should serialize to JSON")
            );
        }
    }
}
