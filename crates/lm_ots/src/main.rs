use lm_ots::{
    bench_message, default_identifier, measure_time, memory,
    seed_bytes_from_u64, seed_from_str, LmOtsParamSet, LmOtsScheme,
    TrackingAllocator, LMOTS_Q,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let param_set = parse_param_set_env("LMOTS_PARAM_SET")?;
    let message_size = parse_usize_env("LMOTS_MESSAGE_SIZE", 1024)?;
    let deterministic = parse_bool_env("LMOTS_DETERMINISTIC", true);

    let scheme = LmOtsScheme::new(param_set);
    let id = default_identifier();
    let message = bench_message(message_size);

    println!(
        "=== {} ({}) Benchmark ===\n",
        scheme.algorithm_name(),
        scheme.param_set_name()
    );
    println!("Backend: {}", scheme.backend_name());
    println!("Deterministic benchmark RNG: {deterministic}");

    println!("\n--- Key Generation ---");
    let ((public_key, mut secret_key), keygen_duration) = measure_time(|| {
        if deterministic {
            scheme.keypair_with_seed(
                LMOTS_Q,
                id,
                seed_bytes_from_u64(seed_from_str("lm-ots-main-keygen")),
            )
        } else {
            scheme.keypair(LMOTS_Q, id)
        }
    });
    print_timing("generate keys", keygen_duration);

    println!("\n--- Signing ---");
    memory::reset_peak();
    let (signature, sign_duration) = measure_time(|| {
        if deterministic {
            scheme.sign_with_seed(
                &message,
                &mut secret_key,
                seed_from_str("lm-ots-main-sign"),
            )
        } else {
            scheme.sign(&message, &mut secret_key)
        }
    });
    let signature = signature?;
    print_timing("sign", sign_duration);
    let sign_peak_mem = memory::peak_bytes();
    println!("Peak memory during signing: {sign_peak_mem} bytes");

    println!("\n--- Verification ---");
    memory::reset_peak();
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify(&message, &signature, &public_key)
            .expect("verify call should succeed")
    });
    print_timing("verify", verify_duration);
    let verify_peak_mem = memory::peak_bytes();
    println!("Peak memory during verification: {verify_peak_mem} bytes");
    println!(
        "Signature verification: {}",
        if verified { "SUCCESS" } else { "FAILED" }
    );

    let sizes = scheme.sizes();
    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", sizes.public_key_bytes);
    println!("Secret key size: {} bytes", sizes.secret_key_bytes);
    println!("Signature size: {} bytes", sizes.signature_bytes);
    println!("Message size: {} bytes", message.len());

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
    println!("  Public Key:  {} bytes", sizes.public_key_bytes);
    println!("  Secret Key:  {} bytes", sizes.secret_key_bytes);
    println!("  Signature:   {} bytes", sizes.signature_bytes);
    println!("  Message:     {} bytes", message.len());
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {sign_peak_mem} bytes");
    println!("  Verification: {verify_peak_mem} bytes");

    Ok(())
}

fn parse_param_set_env(
    name: &str,
) -> Result<LmOtsParamSet, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(LmOtsParamSet::default()),
    }
}

fn parse_usize_env(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => {
            matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
        }
        Err(_) => default,
    }
}
