use sqisign::{
    measure_time, memory, signed_message_size, TrackingAllocator, SQISIGN,
};
use std::alloc::System;
use std::time::Duration;

static SYSTEM_ALLOC: System = System;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> =
    TrackingAllocator::new(&SYSTEM_ALLOC);

const MESSAGE: &[u8] =
    b"This is a test message for SQISign signature scheme benchmarking";

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() {
    let scheme = SQISIGN;
    println!("=== SQISign ({}) Benchmark ===\n", scheme.algorithm_name());

    println!("--- Key Generation ---");
    let (keypair, keygen_duration) = measure_time(|| {
        scheme.keypair().expect("key generation should succeed")
    });
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(&keypair, MESSAGE)
            .expect("signing should succeed")
    });
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify(&keypair, MESSAGE, &signature)
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

    let pk_size = scheme.public_key_size(&keypair);
    let sk_size = scheme.secret_key_size(&keypair);
    let sig_size = scheme.signature_size(&signature);

    println!("\n--- Size Measurements ---");
    println!("Public key size: {pk_size} bytes");
    println!("Secret key size: {sk_size} bytes");
    println!("Signature size: {sig_size} bytes");
    println!(
        "Signed message size: {} bytes",
        signed_message_size(MESSAGE.len(), sig_size)
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
    println!("  Public Key:  {pk_size} bytes");
    println!("  Secret Key:  {sk_size} bytes");
    println!("  Signature:   {sig_size} bytes");
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {sign_peak_mem} bytes");
    println!("  Verification: {verify_peak_mem} bytes");
}
