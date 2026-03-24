use dilithium::{
    default_seed, measure_time, memory, signed_message_size, SignatureScheme,
    TrackingAllocator, ALLOCATION_TRACKER, BENCH_MESSAGE, ML_DSA_65,
};
use pq_bench::{
    print_human_benchmark_report, HumanBenchmarkLine, HumanBenchmarkReport,
    HumanBenchmarkSection,
};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

const MESSAGE: &[u8] = &BENCH_MESSAGE;
const CONTEXT: &[u8] = &[];

fn main() {
    let scheme = ML_DSA_65;
    let seed = default_seed();
    let (keypair, keygen_duration) = measure_time(|| scheme.keypair(&seed));
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(&keypair, MESSAGE, CONTEXT)
            .expect("signing should succeed")
    });
    let sign_peak_mem = memory::peak_bytes();
    memory::reset_peak();
    let (verified, verify_duration) =
        measure_time(|| scheme.verify(&keypair, MESSAGE, CONTEXT, &signature));
    let verify_peak_mem = memory::peak_bytes();

    let pk_size = scheme.public_key_size(&keypair);
    let sk_size = scheme.secret_key_size(&keypair);
    let sig_size = scheme.signature_size(&signature);
    let size_lines = vec![
        HumanBenchmarkLine::bytes("Public key size", pk_size),
        HumanBenchmarkLine::bytes("Secret key size", sk_size),
        HumanBenchmarkLine::bytes("Signature size", sig_size),
        HumanBenchmarkLine::bytes(
            "Signed message size",
            signed_message_size(MESSAGE.len(), sig_size),
        ),
    ];

    print_human_benchmark_report(&HumanBenchmarkReport {
        heading: format!("Dilithium ({})", scheme.algorithm_name()).into(),
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
        size_lines: size_lines.clone(),
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
}
