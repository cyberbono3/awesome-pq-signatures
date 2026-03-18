use std::time::Duration;

use xmssmt_bench::{measure_time, XmssmtParamSet, XmssmtScheme};

const MESSAGE: &[u8] = b"This is a test message for XMSS^MT benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);
    let algorithm_name = format!(
        "{} ({})",
        scheme.param_set().as_str(),
        scheme.backend_name()
    );

    println!("╔══════════════════════════════════════════════════╗");
    println!("║              XMSS^MT Benchmark                   ║");
    println!("║  NIST SP 800-208 Multi-Tree Signature Scheme     ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("=== {} Benchmark ===\n", algorithm_name);

    // --- Key Generation ---
    println!("--- Key Generation ---");
    let (mut kp, keygen_duration) =
        measure_time(|| scheme.keypair().expect("keypair must succeed"));
    print_timing("generate keys", keygen_duration);

    let sizes = scheme.sizes()?;

    // --- Signing ---
    println!("\n--- Signing ---");
    let (signature, sign_duration) = measure_time(|| kp.sign(MESSAGE).expect("sign must succeed"));
    print_timing("sign", sign_duration);

    // --- Verification ---
    println!("\n--- Verification ---");
    let (is_valid, verify_duration) = measure_time(|| {
        kp.verify(MESSAGE, &signature)
            .expect("verify call must succeed")
    });
    print_timing("verify", verify_duration);

    if is_valid {
        println!("Signature verification: SUCCESS");
    } else {
        println!("Signature verification: FAILED");
    }

    // --- Size Measurements ---
    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", sizes.public_key_bytes);
    println!("Secret key size: {} bytes", sizes.secret_key_bytes);
    println!("Signature size:  {} bytes", signature.len());

    // --- Summary ---
    println!("\n=== Summary ===");
    println!("Algorithm: {}", scheme.param_set().as_str());
    println!("\nTiming:");
    println!(
        "  Key Generation: {:?} ({} ns)",
        keygen_duration,
        keygen_duration.as_nanos()
    );
    println!(
        "  Signing:        {:?} ({} ns)",
        sign_duration,
        sign_duration.as_nanos()
    );
    println!(
        "  Verification:   {:?} ({} ns)",
        verify_duration,
        verify_duration.as_nanos()
    );
    println!("\nSizes:");
    println!("  Public Key:  {} bytes", sizes.public_key_bytes);
    println!("  Secret Key:  {} bytes", sizes.secret_key_bytes);
    println!("  Signature:   {} bytes", signature.len());

    Ok(())
}
