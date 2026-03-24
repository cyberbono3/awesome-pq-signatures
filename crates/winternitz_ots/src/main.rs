use pq_bench::{
    benchmark_message, duration_ns, emit_benchmark_report,
    print_human_benchmark_report, BenchmarkBinaryConfig, BenchmarkBinaryReport,
    BenchmarkSizeReport, HumanBenchmarkLine, HumanBenchmarkReport,
    HumanBenchmarkSection,
};
use winternitz_ots::{
    measure_time, memory, SignatureScheme, TrackingAllocator,
    ALLOCATION_TRACKER, WINTERNITZ_OTS,
};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    let config = BenchmarkBinaryConfig::parse(std::env::args().skip(1))
        .unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        });
    let message = benchmark_message(config.message_size);
    let scheme = WINTERNITZ_OTS;
    let (keypair, keygen_duration) = measure_time(|| scheme.keypair());
    memory::reset_peak();
    let (signature, sign_duration) =
        measure_time(|| scheme.sign(&keypair, &message));
    let sign_peak_mem = memory::peak_bytes();
    memory::reset_peak();
    let (verified, verify_duration) =
        measure_time(|| scheme.verify(&signature));
    let verify_peak_mem = memory::peak_bytes();
    let pk_size = scheme.public_key_size(&keypair);
    let sk_size = scheme.secret_key_size(&keypair);
    let sig_size = scheme.signature_size(&signature);
    let signed_input_size = scheme.signed_input_size(&signature);

    let report = BenchmarkBinaryReport {
        algorithm: scheme.algorithm_name().to_string(),
        backend: Some(scheme.backend_name().to_string()),
        param_set: Some(scheme.param_set_name().to_string()),
        keygen_ns: duration_ns(keygen_duration),
        sign_ns: duration_ns(sign_duration),
        verify_ns: duration_ns(verify_duration),
        verified,
        sizes: BenchmarkSizeReport {
            public_key_bytes: pk_size,
            secret_key_bytes: sk_size,
            signature_bytes: sig_size,
            signed_message_bytes: None,
        },
        sign_peak_bytes: Some(sign_peak_mem),
        verify_peak_bytes: Some(verify_peak_mem),
    };

    emit_benchmark_report(&config, &report, |_| {
        print_human_benchmark_report(&HumanBenchmarkReport {
            heading: scheme.algorithm_name().into(),
            intro_lines: vec![
                HumanBenchmarkLine::new("Backend", scheme.backend_name()),
                HumanBenchmarkLine::new("Param set", scheme.param_set_name()),
            ],
            summary_algorithm: scheme.algorithm_name().into(),
            summary_intro_lines: vec![
                HumanBenchmarkLine::new("Backend", scheme.backend_name()),
                HumanBenchmarkLine::new("Param set", scheme.param_set_name()),
            ],
            keygen_duration,
            sign_duration,
            verify_duration,
            sign_detail_lines: vec![HumanBenchmarkLine::bytes(
                "Peak memory during signing",
                sign_peak_mem,
            )],
            verify_detail_lines: vec![HumanBenchmarkLine::bytes(
                "Peak memory during verification",
                verify_peak_mem,
            )],
            verified,
            size_lines: vec![
                HumanBenchmarkLine::bytes("Public key size", pk_size),
                HumanBenchmarkLine::bytes("Secret key size", sk_size),
                HumanBenchmarkLine::bytes("Signature size", sig_size),
                HumanBenchmarkLine::bytes(
                    "Signed digest input size",
                    signed_input_size,
                ),
                HumanBenchmarkLine::bytes("Message size", message.len()),
            ],
            summary_size_lines: vec![
                HumanBenchmarkLine::bytes("Public Key", pk_size),
                HumanBenchmarkLine::bytes("Secret Key", sk_size),
                HumanBenchmarkLine::bytes("Signature", sig_size),
                HumanBenchmarkLine::bytes(
                    "Signed Digest Input",
                    signed_input_size,
                ),
                HumanBenchmarkLine::bytes("Original Message", message.len()),
            ],
            summary_sections: vec![HumanBenchmarkSection {
                title: "Memory Usage (heap allocations)",
                lines: vec![
                    HumanBenchmarkLine::bytes("Signing", sign_peak_mem),
                    HumanBenchmarkLine::bytes("Verification", verify_peak_mem),
                ],
            }],
            ..HumanBenchmarkReport::default()
        });
    });
}
