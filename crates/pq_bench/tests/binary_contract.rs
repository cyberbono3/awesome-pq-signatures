use std::process::Command;

#[test]
fn fixture_binary_emits_valid_json_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_pq_bench_fixture"))
        .args(["--format", "json", "--message-size", "64"])
        .output()
        .expect("fixture binary should execute");

    assert!(
        output.status.success(),
        "fixture binary failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: pq_bench::BenchmarkBinaryReport =
        serde_json::from_slice(&output.stdout)
            .expect("fixture JSON output should deserialize");

    assert_eq!(report.algorithm, "FixtureScheme");
    assert_eq!(report.backend.as_deref(), Some("fixture-backend"));
    assert_eq!(report.param_set.as_deref(), Some("Fixture-Param"));
    assert!(report.verified);
    assert_eq!(report.sizes.public_key_bytes, 12);
    assert_eq!(report.sizes.secret_key_bytes, 34);
    assert_eq!(report.sizes.signature_bytes, 64);
    assert_eq!(report.sizes.signed_message_bytes, Some(128));
}

#[test]
fn fixture_binary_emits_human_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_pq_bench_fixture"))
        .args(["--format", "human", "--message-size", "32"])
        .output()
        .expect("fixture binary should execute");

    assert!(
        output.status.success(),
        "fixture binary failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== FixtureScheme (Fixture-Param) Benchmark ==="));
    assert!(stdout.contains("Signature verification: SUCCESS"));
    assert!(stdout.contains("Public key size: 12 bytes"));
    assert!(stdout.contains("Secret key size: 34 bytes"));
    assert!(stdout.contains("Signature size: 32 bytes"));
    assert!(stdout.contains("Signed message size: 64 bytes"));
}
