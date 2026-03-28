#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_path(prefix: &str, suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}_{}_{}{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos(),
        suffix
    ))
}

fn write_mock_benchmark_binary() -> PathBuf {
    let path = unique_temp_path("bench_runner_cli_mock", "");
    let script = r#"#!/bin/sh
if [ "$1" != "--format" ] || [ "$2" != "json" ] || [ "$3" != "--message-size" ] || [ "$4" != "64" ]; then
  echo "unexpected args: $*" >&2
  exit 2
fi
printf '%s' '{"algorithm":"LeanSig","param_set":"Poseidon-L2^18-TS-w4","keygen_ns":111,"sign_ns":222,"verify_ns":333,"verified":true,"sizes":{"public_key_bytes":444,"secret_key_bytes":555,"signature_bytes":666,"signed_message_bytes":730},"sign_peak_bytes":777,"verify_peak_bytes":888}'
"#;
    std::fs::write(&path, script)
        .expect("mock benchmark binary should be written");
    let mut permissions = std::fs::metadata(&path)
        .expect("mock benchmark binary metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions)
        .expect("mock benchmark binary should be executable");
    path
}

#[test]
fn bench_runner_cli_uses_overridden_subprocess_binary() {
    let mock_binary = write_mock_benchmark_binary();
    let output_path = unique_temp_path("bench_runner_cli_output", ".csv");
    let runner = env!("CARGO_BIN_EXE_bench_runner");

    let output = Command::new(runner)
        .args([
            "--runs",
            "1",
            "--only",
            "leansig",
            "--message-size",
            "64",
            "--output",
            output_path
                .to_str()
                .expect("output path should be valid utf-8"),
        ])
        .env("BENCH_RUNNER_BIN_LEANSIG", &mock_binary)
        .output()
        .expect("bench_runner should execute");

    assert!(
        output.status.success(),
        "bench_runner failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let csv =
        std::fs::read_to_string(&output_path).expect("csv output should exist");
    assert!(
        csv.contains("LeanSig,Poseidon-L2^18-TS-w4,111,222,333,444,555,666")
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Results written to"));
    assert!(stdout.contains("(1/1 algorithms)"));

    let _ = std::fs::remove_file(mock_binary);
    let _ = std::fs::remove_file(output_path);
}
