use dilithium::{
    default_seed, measure_time, memory, signed_message_size, SignatureScheme,
    TrackingAllocator, ALLOCATION_TRACKER, ML_DSA_65,
};
use pq_bench::{
    build_standard_human_benchmark_report, duration_ns,
    run_human_benchmark_binary, BenchmarkBinaryExecution,
    BenchmarkBinaryReport, BenchmarkSizeReport, HumanBenchmarkLine,
    StandardHumanBenchmarkSpec,
};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

const CONTEXT: &[u8] = &[];

fn main() {
    run_human_benchmark_binary(std::env::args().skip(1), |message| {
        let scheme = ML_DSA_65;
        let seed = default_seed();
        let (keypair, keygen_duration) = measure_time(|| scheme.keypair(&seed));
        memory::reset_peak();
        let (signature, sign_duration) = measure_time(|| {
            scheme
                .sign(&keypair, message, CONTEXT)
                .expect("signing should succeed")
        });
        let sign_peak_mem = memory::peak_bytes();
        memory::reset_peak();
        let (verified, verify_duration) = measure_time(|| {
            scheme.verify(&keypair, message, CONTEXT, &signature)
        });
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
                signed_message_size(message.len(), sig_size),
            ),
        ];

        BenchmarkBinaryExecution {
            report: BenchmarkBinaryReport {
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
                    signed_message_bytes: Some(signed_message_size(
                        message.len(),
                        sig_size,
                    )),
                },
                sign_peak_bytes: Some(sign_peak_mem),
                verify_peak_bytes: Some(verify_peak_mem),
            },
            human: build_standard_human_benchmark_report(
                StandardHumanBenchmarkSpec {
                    banner_lines: &[],
                    heading: format!("Dilithium ({})", scheme.algorithm_name())
                        .into(),
                    intro_lines: Vec::new(),
                    summary_algorithm: scheme.algorithm_name().into(),
                    summary_intro_lines: Vec::new(),
                    keygen_duration,
                    sign_duration,
                    verify_duration,
                    verified,
                    size_lines,
                    summary_size_lines: vec![
                        HumanBenchmarkLine::bytes("Public Key", pk_size),
                        HumanBenchmarkLine::bytes("Secret Key", sk_size),
                        HumanBenchmarkLine::bytes("Signature", sig_size),
                    ],
                    sign_peak_bytes: Some(sign_peak_mem),
                    verify_peak_bytes: Some(verify_peak_mem),
                },
            ),
        }
    });
}
