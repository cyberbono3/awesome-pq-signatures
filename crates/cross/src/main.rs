use cross::{measure_time, memory, signed_message_size, TrackingAllocator, CROSS};
use std::alloc::System;
use std::time::Duration;

static SYSTEM_ALLOC: System = System;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> = TrackingAllocator::new(&SYSTEM_ALLOC);

const MESSAGE: &[u8] = b"This is a test message for CROSS signature scheme benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() {
    let scheme = CROSS;
    println!("=== CROSS ({}) Benchmark ===\n", scheme.algorithm_name());

    println!("--- Key Generation ---");
    let (keypair, keygen_duration) = measure_time(|| {
        scheme
            .benchmark_keypair()
            .expect("key generation should succeed")
    });
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign_message(&keypair, MESSAGE)
            .expect("signing should succeed")
    });
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify_message(&keypair, MESSAGE, &signature)
            .expect("verification should succeed")
    });
    print_timing("verify", verify_duration);
    let verify_peak_mem = memory::peak_bytes();
    println!("Peak memory during verification: {verify_peak_mem} bytes");

    if verified {
        println!("Signature verification: SUCCESS");
    } else {
        println!("Signature verification: FAILED");
    }

    let sizes = scheme.sizes(&keypair, &signature);

    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", sizes.public_key);
    println!("Secret key size: {} bytes", sizes.secret_key);
    println!("Signature size: {} bytes", sizes.signature);
    println!(
        "Signed message size: {} bytes",
        signed_message_size(MESSAGE.len(), sizes.signature)
    );

    println!("\n=== Summary ===");
    println!("Algorithm: {}", scheme.algorithm_name());
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
    println!("  Public Key:  {} bytes", sizes.public_key);
    println!("  Secret Key:  {} bytes", sizes.secret_key);
    println!("  Signature:   {} bytes", sizes.signature);
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {sign_peak_mem} bytes");
    println!("  Verification: {verify_peak_mem} bytes");
}
