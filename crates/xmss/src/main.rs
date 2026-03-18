use std::time::Duration;

use xmss_bench::default_benchmark_scheme;

const MESSAGE: &[u8] = b"This is a test message for XMSS benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() {
    let scheme = default_benchmark_scheme();
    let report = scheme
        .benchmark_report(MESSAGE)
        .expect("xmss benchmark report must succeed");

    println!("╔══════════════════════════════════════════════════╗");
    println!("║              XMSS Benchmark                      ║");
    println!("║  NIST SP 800-208 Hash-Based Signature Scheme    ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("=== {} Benchmark ===\n", report.display_name);
    println!("--- Key Generation ---");
    print_timing("generate keys", report.keygen_duration);
    println!("\n--- Signing ---");
    print_timing("sign", report.sign_duration);
    println!("\n--- Verification ---");
    print_timing("verify", report.verify_duration);

    if report.verified {
        println!("Signature verification: SUCCESS");
    } else {
        println!("Signature verification: FAILED");
    }

    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", report.public_key_size);
    println!("Secret key size: {} bytes", report.secret_key_size);
    println!("Signature size:  {} bytes", report.signature_size);

    println!("\n=== Summary ===");
    println!("Algorithm: {}", report.param_set.as_str());
    println!("\nTiming:");
    println!(
        "  Key Generation: {:?} ({} ns)",
        report.keygen_duration,
        report.keygen_duration.as_nanos()
    );
    println!(
        "  Signing:        {:?} ({} ns)",
        report.sign_duration,
        report.sign_duration.as_nanos()
    );
    println!(
        "  Verification:   {:?} ({} ns)",
        report.verify_duration,
        report.verify_duration.as_nanos()
    );
    println!("\nSizes:");
    println!("  Public Key:  {} bytes", report.public_key_size);
    println!("  Secret Key:  {} bytes", report.secret_key_size);
    println!("  Signature:   {} bytes", report.signature_size);
}
