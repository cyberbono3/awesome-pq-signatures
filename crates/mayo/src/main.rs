use mayo::{
    measure_time, memory, signed_message_size, TrackingAllocator,
    ALLOCATION_TRACKER, MAYO,
};
use pq_bench::{
    build_standard_benchmark_execution, run_human_benchmark_binary,
    HumanBenchmarkLine, StandardBenchmarkExecutionSpec,
};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let scheme = MAYO;
        let (keypair, keygen_duration) =
            measure_time(|| scheme.benchmark_keypair());
        memory::reset_peak();
        let (signature, sign_duration) = measure_time(|| {
            scheme
                .sign_message(&keypair, message)
                .expect("signing should succeed")
        });
        let sign_peak_mem = memory::peak_bytes();
        memory::reset_peak();
        let (verified, verify_duration) = measure_time(|| {
            scheme.verify_message(&keypair, message, &signature)
        });
        let verify_peak_mem = memory::peak_bytes();

        let sizes = scheme.sizes(&keypair, &signature);
        let size_lines = vec![
            HumanBenchmarkLine::bytes(
                "Public key size",
                sizes.public_key_bytes,
            ),
            HumanBenchmarkLine::bytes(
                "Secret key size",
                sizes.secret_key_bytes,
            ),
            HumanBenchmarkLine::bytes("Signature size", sizes.signature_bytes),
            HumanBenchmarkLine::bytes(
                "Signed message size",
                signed_message_size(message.len(), sizes.signature_bytes),
            ),
        ];

        build_standard_benchmark_execution(StandardBenchmarkExecutionSpec {
            banner_lines: &[],
            heading: format!("MAYO ({})", scheme.algorithm_name()).into(),
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
            public_key_bytes: sizes.public_key_bytes,
            secret_key_bytes: sizes.secret_key_bytes,
            signature_bytes: sizes.signature_bytes,
            signed_message_bytes: Some(signed_message_size(
                message.len(),
                sizes.signature_bytes,
            )),
            size_lines,
            summary_size_lines: vec![
                HumanBenchmarkLine::bytes("Public Key", sizes.public_key_bytes),
                HumanBenchmarkLine::bytes("Secret Key", sizes.secret_key_bytes),
                HumanBenchmarkLine::bytes("Signature", sizes.signature_bytes),
            ],
            sign_peak_bytes: Some(sign_peak_mem),
            verify_peak_bytes: Some(verify_peak_mem),
        })
    });
}
