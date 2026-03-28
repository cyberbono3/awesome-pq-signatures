use falcon::{
    measure_time, memory, signature_size, SignatureScheme, TrackingAllocator,
    ALLOCATION_TRACKER, FALCON512,
};
use pq_bench::{
    build_standard_benchmark_execution, run_human_benchmark_binary,
    HumanBenchmarkLine, StandardBenchmarkExecutionSpec,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let scheme = FALCON512;
        let ((public_key, secret_key), keygen_duration) =
            measure_time(|| scheme.keypair());
        memory::reset_peak();
        let (signed_message, sign_duration) =
            measure_time(|| scheme.sign(message, &secret_key));
        let sign_peak_mem = memory::peak_bytes();
        memory::reset_peak();
        let (opened_message, verify_duration) =
            measure_time(|| scheme.open(&signed_message, &public_key));
        let verify_peak_mem = memory::peak_bytes();

        let verified =
            matches!(opened_message, Some(opened) if opened == message);
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

        build_standard_benchmark_execution(StandardBenchmarkExecutionSpec {
            banner_lines: &[],
            heading: scheme.algorithm_name().into(),
            intro_lines: Vec::new(),
            algorithm: scheme.algorithm_name(),
            backend: None,
            param_set: Some(scheme.algorithm_name()),
            summary_algorithm: scheme.algorithm_name().into(),
            summary_intro_lines: Vec::new(),
            keygen_duration,
            sign_duration,
            verify_duration,
            verified,
            public_key_bytes: pk_size,
            secret_key_bytes: sk_size,
            signature_bytes: sig_size,
            signed_message_bytes: Some(signed_message.as_bytes().len()),
            size_lines,
            summary_size_lines: vec![
                HumanBenchmarkLine::bytes("Public Key", pk_size),
                HumanBenchmarkLine::bytes("Secret Key", sk_size),
                HumanBenchmarkLine::bytes("Signature", sig_size),
            ],
            sign_peak_bytes: Some(sign_peak_mem),
            verify_peak_bytes: Some(verify_peak_mem),
        })
    });
}
