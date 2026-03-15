use std::time::Duration;

use xmss_bench::{measure_time, XmssParamSet, XmssScheme};

const MESSAGE: &[u8] = b"This is a test message for XMSS signature scheme benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scheme = XmssScheme::new(XmssParamSet::XmssSha2_10_256);
    let algorithm_name = format!(
        "{} ({})",
        scheme.param_set().as_str(),
        scheme.backend_name()
    );

    println!("=== {} Benchmark ===\n", algorithm_name);

    // --- Key Generation ---
    println!("--- Key Generation ---");
    let ((public_key, mut secret_key), keygen_duration) =
        measure_time(|| scheme.keypair().expect("keypair must succeed"));
    print_timing("generate keys", keygen_duration);

    // --- Signing ---
    println!("\n--- Signing ---");
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(MESSAGE, &mut secret_key)
            .expect("sign must succeed")
    });
    print_timing("sign", sign_duration);

    // --- Verification ---
    println!("\n--- Verification ---");
    let (is_valid, verify_duration) = measure_time(|| {
        scheme
            .verify(MESSAGE, &signature, &public_key)
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
    println!("Public key size: {} bytes", public_key.len());
    println!("Secret key size: {} bytes", secret_key.len());
    println!("Signature size: {} bytes", signature.len());

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
    println!("  Public Key:  {} bytes", public_key.len());
    println!("  Secret Key:  {} bytes", secret_key.len());
    println!("  Signature:   {} bytes", signature.len());

    Ok(())
}
