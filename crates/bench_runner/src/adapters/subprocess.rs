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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    fn write_mock_executable(body: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bench_runner_mock_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));

        let script = format!("#!/bin/sh\n{body}\n");
        std::fs::write(&path, script)
            .expect("mock executable should be written");

        let mut permissions = std::fs::metadata(&path)
            .expect("mock executable metadata should be readable")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions)
            .expect("mock executable should be made executable");

        path
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_adapter_parses_benchmark_json() {
        let executable = write_mock_executable(
            r#"printf '%s' '{"algorithm":"Mock","param_set":"Mock-1","keygen_ns":11,"sign_ns":22,"verify_ns":33,"verified":true,"sizes":{"public_key_bytes":44,"secret_key_bytes":55,"signature_bytes":66,"signed_message_bytes":77},"sign_peak_bytes":88,"verify_peak_bytes":99}'"#,
        );

        let adapter = SubprocessAdapter {
            algorithm: "Mock",
            param_set: "Mock-1",
            executable: executable.clone(),
            message_size: 64,
        };

        let run = adapter
            .run_once(b"ignored-by-subprocess")
            .expect("subprocess benchmark should succeed");

        assert_eq!(
            run,
            BenchRun {
                keygen_ns: 11,
                sign_ns: 22,
                verify_ns: 33,
                sizes: crate::types::SizeMetrics::new(44, 55, 66),
            }
        );

        let _ = std::fs::remove_file(executable);
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_adapter_reports_invalid_json() {
        let executable = write_mock_executable("printf '%s' 'not-json'");

        let adapter = SubprocessAdapter {
            algorithm: "Mock",
            param_set: "Mock-1",
            executable: executable.clone(),
            message_size: 64,
        };

        let err = adapter
            .run_once(b"ignored-by-subprocess")
            .expect_err("invalid JSON should fail");

        assert!(err.contains("invalid benchmark JSON"));

        let _ = std::fs::remove_file(executable);
    }
}
