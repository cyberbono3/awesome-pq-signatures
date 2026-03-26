use std::process::Command;

use pq_bench::BenchmarkBinaryReport;

use crate::registry::AdapterSpec;
use crate::types::{BenchRun, DsaBenchmark};

use super::shared::RunnerContext;

pub struct SubprocessAdapter {
    pub algorithm: &'static str,
    pub param_set: &'static str,
    pub executable: std::path::PathBuf,
    pub message_size: usize,
}

impl DsaBenchmark for SubprocessAdapter {
    fn name(&self) -> &str {
        self.algorithm
    }

    fn param_set(&self) -> &str {
        self.param_set
    }

    fn run_once(&self, _message: &[u8]) -> Result<BenchRun, String> {
        let output = Command::new(&self.executable)
            .args([
                "--format",
                "json",
                "--message-size",
                &self.message_size.to_string(),
            ])
            .output()
            .map_err(|err| {
                format!(
                    "failed to execute {}: {err}",
                    self.executable.display()
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "exit {}: {}",
                output.status,
                stderr.lines().last().unwrap_or("")
            ));
        }

        let report: BenchmarkBinaryReport =
            serde_json::from_slice(&output.stdout)
                .map_err(|err| format!("invalid benchmark JSON: {err}"))?;

        Ok(BenchRun::from_binary_report(&report))
    }
}

pub fn build_binary_adapter(
    context: &RunnerContext,
    spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(SubprocessAdapter {
        algorithm: spec.algorithm,
        param_set: spec.param_set,
        executable: context
            .binary_executables
            .get(spec.algorithm)
            .expect("binary executable should be resolved")
            .clone(),
        message_size: context.message_size,
    })
}
