use pq_bench::print_timing;
use pq_bench::{
    benchmark_message, duration_ns, emit_benchmark_report,
    BenchmarkBinaryConfig, BenchmarkBinaryReport, BenchmarkSizeReport,
};
use sqisign::{
    measure_time, memory, signed_message_size, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE, SQISIGN,
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
    let message = if config.message_size == BENCH_MESSAGE.len() {
        BENCH_MESSAGE.to_vec()
    } else {
        message
    };
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
    let report = BenchmarkBinaryReport {
        algorithm: "SQISign".to_string(),
        backend: None,
        param_set: Some("SQISign-lvl1".to_string()),
        keygen_ns: duration_ns(keygen_duration),
        sign_ns: duration_ns(sign_duration),
        verify_ns: duration_ns(verify_duration),
        verified,
        sizes: BenchmarkSizeReport {
            public_key_bytes: sizes.public_key,
            secret_key_bytes: sizes.secret_key,
            signature_bytes: sizes.signature,
            signed_message_bytes: Some(signed_message_size(
                message.len(),
                sizes.signature,
            )),
        },
        sign_peak_bytes: Some(sign_peak_mem),
        verify_peak_bytes: Some(verify_peak_mem),
    };

    emit_benchmark_report(&config, &report, |report| {
        println!("=== SQISign ({}) Benchmark ===\n", scheme.algorithm_name());
        println!("--- Key Generation ---");
        print_timing("generate keys", keygen_duration);
        println!("\n--- Signing ---");
        print_timing("sign", sign_duration);
        println!("Peak memory during signing: {sign_peak_mem} bytes");
        println!("\n--- Verification ---");
        print_timing("verify", verify_duration);
        println!("Peak memory during verification: {verify_peak_mem} bytes");

        if report.verified {
            println!("Signature verification: SUCCESS");
        } else {
            println!("Signature verification: FAILED");
        }

        println!("\n--- Size Measurements ---");
        println!("Public key size: {} bytes", sizes.public_key);
        println!("Secret key size: {} bytes", sizes.secret_key);
        println!("Signature size: {} bytes", sizes.signature);
        println!(
            "Signed message size: {} bytes",
            report
                .sizes
                .signed_message_bytes
                .expect("signed message size should exist")
        );

        println!("\n=== Summary ===");
        println!("Algorithm: {}", scheme.algorithm_name());
        println!("\nTiming:");
        println!(
            "  Key Generation: {:?} ({} ns)",
            keygen_duration, report.keygen_ns
        );
        println!(
            "  Signing:        {:?} ({} ns)",
            sign_duration, report.sign_ns
        );
        println!(
            "  Verification:   {:?} ({} ns)",
            verify_duration, report.verify_ns
        );
        println!("\nSizes:");
        println!("  Public Key:  {} bytes", sizes.public_key);
        println!("  Secret Key:  {} bytes", sizes.secret_key);
        println!("  Signature:   {} bytes", sizes.signature);
        println!("\nMemory Usage (heap allocations):");
        println!("  Signing:      {sign_peak_mem} bytes");
        println!("  Verification: {verify_peak_mem} bytes");
    });
}
