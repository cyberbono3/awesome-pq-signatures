use pq_bench::{
    print_human_benchmark_report, HumanBenchmarkLine, HumanBenchmarkReport,
    HumanBenchmarkSection,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use sphincs_plus::{
    measure_time, memory, signature_size, SignatureScheme, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE, SPHINCS_PLUS_SHAKE_128F_SIMPLE,
};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

const MESSAGE: &[u8] = &BENCH_MESSAGE;

fn main() {
    let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
    let ((public_key, secret_key), keygen_duration) =
        measure_time(|| scheme.keypair());
    memory::reset_peak();
    let (signed_message, sign_duration) =
        measure_time(|| scheme.sign(MESSAGE, &secret_key));
    let sign_peak_mem = memory::peak_bytes();
    memory::reset_peak();
    let (opened_message, verify_duration) =
        measure_time(|| scheme.open(&signed_message, &public_key));
    let verify_peak_mem = memory::peak_bytes();

    let verified =
        matches!(opened_message, Some(message) if message == MESSAGE);
    let pk_size = public_key.as_bytes().len();
    let sk_size = secret_key.as_bytes().len();
    let sig_size = signature_size(&signed_message, MESSAGE.len());

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
        size_lines: vec![
            HumanBenchmarkLine::bytes("Public key size", pk_size),
            HumanBenchmarkLine::bytes("Secret key size", sk_size),
            HumanBenchmarkLine::bytes("Signature size", sig_size),
            HumanBenchmarkLine::bytes(
                "Signed message size",
                signed_message.as_bytes().len(),
            ),
        ],
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
