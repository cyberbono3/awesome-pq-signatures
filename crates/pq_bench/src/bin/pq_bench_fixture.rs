use pq_bench::{
    run_standard_signed_message_benchmark_binary, StandardBenchmarkSizes,
    StandardSignedMessageBinaryLabels,
};

fn main() {
    run_standard_signed_message_benchmark_binary(
        std::env::args().skip(1),
        StandardSignedMessageBinaryLabels {
            algorithm: "FixtureScheme",
            param_set: "Fixture-Param",
            heading_algorithm: "FixtureScheme",
            heading_param_set: "Fixture-Param",
            summary_algorithm: "FixtureScheme",
            backend: Some("fixture-backend"),
        },
        || vec![1_u8, 2, 3, 4],
        |_keypair, message| message.to_vec(),
        |_keypair, message, signature| signature == message,
        |_keypair, signature| StandardBenchmarkSizes {
            public_key_bytes: 12,
            secret_key_bytes: 34,
            signature_bytes: signature.len(),
        },
        || {},
        || 0,
    );
}
