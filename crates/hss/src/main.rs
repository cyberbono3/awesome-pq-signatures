use hss::{
    default_param_set_name, default_seed, measure_time, signed_message_size, HssScheme,
    BENCH_MESSAGE,
};
use std::env;
use std::time::Duration;

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

fn main() {
    let param_set_name = env::var("PARAM_SET").unwrap_or_else(|_| default_param_set_name().to_owned());
    let scheme = HssScheme::from_param_set_name(&param_set_name).expect("valid HSS parameter set");
    let message: &[u8] = &BENCH_MESSAGE;
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
    let (signature, sign_duration) = measure_time(|| {
        scheme
            .sign(&message, &mut secret_key)
            .expect("HSS signing should succeed")
    });
    print_timing("sign", sign_duration);

    println!("\n--- Verification ---");
    let (verified, verify_duration) = measure_time(|| {
        scheme
            .verify(&message, &signature, &public_key)
            .expect("HSS verify call should succeed")
    });
    print_timing("verify", verify_duration);

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
}
