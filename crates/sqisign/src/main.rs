use pq_bench::{
    run_standard_signed_message_benchmark_binary, StandardBenchmarkSizes,
    StandardSignedMessageBinaryLabels,
};
use sqisign::{memory, TrackingAllocator, ALLOCATION_TRACKER, SQISIGN};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    let scheme = SQISIGN;
    run_standard_signed_message_benchmark_binary(
        std::env::args().skip(1),
        StandardSignedMessageBinaryLabels {
            algorithm: "SQISign",
            param_set: "SQISign-lvl1",
            heading_algorithm: "SQISign",
            heading_param_set: scheme.algorithm_name(),
            summary_algorithm: scheme.algorithm_name(),
            backend: None,
        },
        || {
            scheme
                .benchmark_keypair()
                .expect("key generation should succeed")
        },
        |keypair, message| {
            scheme
                .sign_message(keypair, message)
                .expect("signing should succeed")
        },
        |keypair, message, signature| {
            scheme
                .verify_message(keypair, message, signature)
                .expect("verification should succeed")
        },
        |keypair, signature| {
            let sizes = scheme.sizes(keypair, signature);
            StandardBenchmarkSizes {
                public_key_bytes: sizes.public_key,
                secret_key_bytes: sizes.secret_key,
                signature_bytes: sizes.signature,
            }
        },
        memory::reset_peak,
        memory::peak_bytes,
    );
}
