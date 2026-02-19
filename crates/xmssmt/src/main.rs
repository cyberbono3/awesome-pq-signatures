use std::alloc::System;
use std::env;
use std::error::Error;
use std::time::Duration;
use xmssmt::{
    bench_message, measure_time, memory, TrackingAllocator, XmssmtScheme,
    DEFAULT_PARAM_SET_NAME,
};

static SYSTEM_ALLOC: System = System;

#[global_allocator]
static GLOBAL: TrackingAllocator<System> =
    TrackingAllocator::new(&SYSTEM_ALLOC);

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn parse_usize_env(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let param_set_name = env::var("PARAM_SET")
        .unwrap_or_else(|_| DEFAULT_PARAM_SET_NAME.to_owned());
    let message_size = parse_usize_env("MESSAGE_SIZE", 1024)?;
    let scheme = XmssmtScheme::from_param_set_name(&param_set_name)?;
    let message = bench_message(message_size);

    println!(
        "=== {} ({}) Benchmark ===\n",
        scheme.algorithm_name(),
        scheme.param_set_name()
    );
    println!("Backend: {}", scheme.backend_name());
    println!("Signatures per key: {}", scheme.signatures_per_key());

    println!("\n--- Key Generation ---");
    let ((public_key, mut secret_key), keygen_duration) =
        measure_time(|| scheme.keypair());
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(&message, &mut secret_key)
            .expect("xmssmt sign should succeed")
    });
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify(&message, &signature, &public_key)
            .expect("xmssmt verify should succeed")
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

    println!("\n--- Size Measurements ---");
    println!("Public key size: {pk_size} bytes");
    println!("Secret key size: {sk_size} bytes");
    println!("Signature size: {sig_size} bytes");
    println!("Message size: {} bytes", message.len());

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

    Ok(())
}
