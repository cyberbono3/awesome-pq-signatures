use std::alloc::System;
use std::time::Duration;
use winternitz_ots::{
    measure_time, memory, SignatureScheme, TrackingAllocator, WINTERNITZ_OTS,
};

static SYSTEM_ALLOC: System = System;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> =
    TrackingAllocator::new(&SYSTEM_ALLOC);

const MESSAGE: &[u8] =
    b"This is a test message for Winternitz OTS signature scheme benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() {
    let scheme = WINTERNITZ_OTS;
    println!("=== {} Benchmark ===\n", scheme.algorithm_name());
    println!("Backend: {}", scheme.backend_name());
    println!("Param set: {}", scheme.param_set_name());

    println!("\n--- Key Generation ---");
    let (keypair, keygen_duration) = measure_time(|| scheme.keypair());
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signature, sign_duration) =
        measure_time(|| scheme.sign(&keypair, MESSAGE));
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (verified, verify_duration) =
        measure_time(|| scheme.verify(&signature));
    print_timing("verify", verify_duration);
    let verify_peak_mem = memory::peak_bytes();
    println!("Peak memory during verification: {verify_peak_mem} bytes");
    println!(
        "Signature verification: {}",
        if verified { "SUCCESS" } else { "FAILED" }
    );

    println!("\n--- Size Measurements ---");
    println!(
        "Public key size: {} bytes",
        scheme.public_key_size(&keypair)
    );
    println!(
        "Secret key size: {} bytes",
        scheme.secret_key_size(&keypair)
    );
    println!(
        "Signature size: {} bytes",
        scheme.signature_size(&signature)
    );
    println!(
        "Signed digest input size: {} bytes",
        scheme.signed_input_size(&signature)
    );
    println!("Message size: {} bytes", MESSAGE.len());

    println!("\n=== Summary ===");
    println!("Algorithm: {}", scheme.algorithm_name());
    println!("Backend: {}", scheme.backend_name());
    println!("Param set: {}", scheme.param_set_name());
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
    println!(
        "  Public Key:          {} bytes",
        scheme.public_key_size(&keypair)
    );
    println!(
        "  Secret Key:          {} bytes",
        scheme.secret_key_size(&keypair)
    );
    println!(
        "  Signature:           {} bytes",
        scheme.signature_size(&signature)
    );
    println!(
        "  Signed Digest Input: {} bytes",
        scheme.signed_input_size(&signature)
    );
    println!("  Original Message:    {} bytes", MESSAGE.len());
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {sign_peak_mem} bytes");
    println!("  Verification: {verify_peak_mem} bytes");
}
