use falcon::{
    measure_time, memory, signature_size, SignatureScheme, TrackingAllocator,
    FALCON512,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use std::alloc::System;
use std::time::Duration;

static SYSTEM_ALLOC: System = System;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> =
    TrackingAllocator::new(&SYSTEM_ALLOC);

const MESSAGE: &[u8] =
    b"This is a test message for Falcon signature scheme benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() {
    let scheme = FALCON512;
    println!("=== {} Benchmark ===\n", scheme.algorithm_name());

    println!("--- Key Generation ---");
    let ((public_key, secret_key), keygen_duration) =
        measure_time(|| scheme.keypair());
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signed_message, sign_duration) =
        measure_time(|| scheme.sign(MESSAGE, &secret_key));
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (opened_message, verify_duration) =
        measure_time(|| scheme.open(&signed_message, &public_key));
    print_timing("verify", verify_duration);
    let verify_peak_mem = memory::peak_bytes();
    println!("Peak memory during verification: {verify_peak_mem} bytes");

    match opened_message {
        Some(message) if message == MESSAGE => {
            println!("Signature verification: SUCCESS")
        }
        Some(_) => {
            println!("Signature verification: FAILED (message mismatch)")
        }
        None => println!("Signature verification: FAILED"),
    }

    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", public_key.as_bytes().len());
    println!("Secret key size: {} bytes", secret_key.as_bytes().len());
    println!(
        "Signature size: {} bytes",
        signature_size(&signed_message, MESSAGE.len())
    );
    println!(
        "Signed message size: {} bytes",
        signed_message.as_bytes().len()
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
    println!("  Public Key:  {} bytes", public_key.as_bytes().len());
    println!("  Secret Key:  {} bytes", secret_key.as_bytes().len());
    println!(
        "  Signature:   {} bytes",
        signature_size(&signed_message, MESSAGE.len())
    );
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {sign_peak_mem} bytes");
    println!("  Verification: {verify_peak_mem} bytes");
}
