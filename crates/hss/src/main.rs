use hss::{
    bench_message, default_seed, measure_time, memory, signed_message_size,
    HssScheme, TrackingAllocator, DEFAULT_PARAM_SET_NAME,
};
use std::alloc::System;
use std::env;
use std::time::Duration;

static SYSTEM_ALLOC: System = System;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> =
    TrackingAllocator::new(&SYSTEM_ALLOC);

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn main() {
    let param_set_name = env::var("PARAM_SET")
        .unwrap_or_else(|_| DEFAULT_PARAM_SET_NAME.to_owned());
    let message_size = parse_usize_env("MESSAGE_SIZE", 1024);
    let scheme = HssScheme::from_param_set_name(&param_set_name)
        .expect("valid HSS parameter set");
    let message = bench_message(message_size);
    let seed = default_seed();

    println!("=== HSS ({}) Benchmark ===\n", scheme.param_set_name());
    println!("Backend: {}", scheme.backend_name());
    println!("Hierarchy levels: {}", scheme.levels());

    println!("\n--- Key Generation ---");
    let ((public_key, mut secret_key), keygen_duration) = measure_time(|| {
        scheme
            .keypair_with_seed(seed)
            .expect("HSS key generation should succeed")
    });
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(&message, &mut secret_key)
            .expect("HSS signing should succeed")
    });
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify(&message, &signature, &public_key)
            .expect("HSS verify call should succeed")
    });
    print_timing("verify", verify_duration);
    let verify_peak_mem = memory::peak_bytes();
    println!("Peak memory during verification: {verify_peak_mem} bytes");

    if verified {
        println!("Signature verification: SUCCESS");
    } else {
        println!("Signature verification: FAILED");
    }

    let pk_size = scheme.public_key_size(&public_key);
    let sk_size = scheme.secret_key_size(&secret_key);
    let sig_size = scheme.signature_size(&signature);
    let key_lifetime = secret_key
        .lifetime()
        .expect("HSS key lifetime should be available");

    println!("\n--- Size Measurements ---");
    println!("Public key size: {pk_size} bytes");
    println!("Secret key size: {sk_size} bytes");
    println!("Signature size: {sig_size} bytes");
    println!(
        "Signed message size: {} bytes",
        signed_message_size(message.len(), sig_size)
    );
    println!("Estimated signatures per key: {key_lifetime}");

    println!("\n=== Summary ===");
    println!("Algorithm: {}", scheme.algorithm_name());
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
    println!("  Public Key:  {pk_size} bytes");
    println!("  Secret Key:  {sk_size} bytes");
    println!("  Signature:   {sig_size} bytes");
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {sign_peak_mem} bytes");
    println!("  Verification: {verify_peak_mem} bytes");
}
