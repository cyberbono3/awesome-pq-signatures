use falcon::{
    measure_time, memory, signature_size, SignatureScheme, TrackingAllocator,
    ALLOCATION_TRACKER, FALCON512,
};
use pq_bench::{
    benchmark_message, duration_ns, emit_benchmark_report,
    print_human_benchmark_report, BenchmarkBinaryConfig, BenchmarkBinaryReport,
    BenchmarkSizeReport, HumanBenchmarkLine, HumanBenchmarkReport,
    HumanBenchmarkSection,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
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
    let scheme = FALCON512;
    let ((public_key, secret_key), keygen_duration) =
        measure_time(|| scheme.keypair());
    memory::reset_peak();
    let (signed_message, sign_duration) =
        measure_time(|| scheme.sign(&message, &secret_key));
    let sign_peak_mem = memory::peak_bytes();
    memory::reset_peak();
    let (opened_message, verify_duration) =
        measure_time(|| scheme.open(&signed_message, &public_key));
    let verify_peak_mem = memory::peak_bytes();

    let verified = matches!(opened_message, Some(opened) if opened == message);
    let pk_size = public_key.as_bytes().len();
    let sk_size = secret_key.as_bytes().len();
    let sig_size = signature_size(&signed_message, message.len());
    let size_lines = vec![
        HumanBenchmarkLine::bytes("Public key size", pk_size),
        HumanBenchmarkLine::bytes("Secret key size", sk_size),
        HumanBenchmarkLine::bytes("Signature size", sig_size),
        HumanBenchmarkLine::bytes(
            "Signed message size",
            signed_message.as_bytes().len(),
        ),
    ];
    let report = BenchmarkBinaryReport {
        algorithm: scheme.algorithm_name().to_string(),
        backend: None,
        param_set: Some(scheme.algorithm_name().to_string()),
        keygen_ns: duration_ns(keygen_duration),
        sign_ns: duration_ns(sign_duration),
        verify_ns: duration_ns(verify_duration),
        verified,
        sizes: BenchmarkSizeReport {
            public_key_bytes: pk_size,
            secret_key_bytes: sk_size,
            signature_bytes: sig_size,
            signed_message_bytes: Some(signed_message.as_bytes().len()),
        },
        sign_peak_bytes: Some(sign_peak_mem),
        verify_peak_bytes: Some(verify_peak_mem),
    };

    emit_benchmark_report(&config, &report, |_| {
        print_human_benchmark_report(&HumanBenchmarkReport {
            heading: scheme.algorithm_name().into(),
            summary_algorithm: scheme.algorithm_name().into(),
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
            size_lines,
            summary_size_lines: vec![
                HumanBenchmarkLine::bytes("Public Key", pk_size),
                HumanBenchmarkLine::bytes("Secret Key", sk_size),
                HumanBenchmarkLine::bytes("Signature", sig_size),
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
