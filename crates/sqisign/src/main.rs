use pq_bench::{
    benchmark_message, build_standard_binary_report,
    emit_standard_benchmark_report, BenchmarkBinaryConfig,
    StandardBenchmarkHumanReport, StandardBinaryBenchmarkSpec,
};
use sqisign::{
    measure_time, memory, signed_message_size, TrackingAllocator,
    ALLOCATION_TRACKER, SQISIGN,
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
    let scheme = SQISIGN;
    let (keypair, keygen_duration) = measure_time(|| {
        scheme
            .benchmark_keypair()
            .expect("key generation should succeed")
    });
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign_message(&keypair, &message)
            .expect("signing should succeed")
    });
    let sign_peak_mem = memory::peak_bytes();
    memory::reset_peak();
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify_message(&keypair, &message, &signature)
            .expect("verification should succeed")
    });
    let verify_peak_mem = memory::peak_bytes();
    let sizes = scheme.sizes(&keypair, &signature);
    let report = build_standard_binary_report(StandardBinaryBenchmarkSpec {
        algorithm: "SQISign",
        backend: None,
        param_set: Some("SQISign-lvl1"),
        keygen_duration,
        sign_duration,
        verify_duration,
        verified,
        public_key_bytes: sizes.public_key,
        secret_key_bytes: sizes.secret_key,
        signature_bytes: sizes.signature,
        signed_message_bytes: Some(signed_message_size(
            message.len(),
            sizes.signature,
        )),
        sign_peak_bytes: Some(sign_peak_mem),
        verify_peak_bytes: Some(verify_peak_mem),
    });

    emit_standard_benchmark_report(
        &config,
        &report,
        StandardBenchmarkHumanReport {
            heading_algorithm: "SQISign",
            heading_param_set: scheme.algorithm_name(),
            summary_algorithm: scheme.algorithm_name(),
            keygen_duration,
            sign_duration,
            verify_duration,
            public_key_bytes: sizes.public_key,
            secret_key_bytes: sizes.secret_key,
            signature_bytes: sizes.signature,
            sign_peak_bytes: sign_peak_mem,
            verify_peak_bytes: verify_peak_mem,
        },
    );
}
