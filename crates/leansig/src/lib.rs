use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::signature::SignatureSchemeSecretKey;
use leansig::MESSAGE_LENGTH;
use std::time::{Duration, Instant};

/// Canonical 32-byte message (SHA-256 digest) that every DSA crate signs.
pub use pq_config::BENCH_MESSAGE;

/// Measure wall-clock time of a closure.
pub fn measure_time<T, F>(operation: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

/// Advance secret-key preparation until `epoch` is inside the prepared
/// interval.
pub fn prepare_sk_for_epoch<SK: SignatureSchemeSecretKey>(sk: &mut SK, epoch: u32) {
    let mut iterations = 0u32;
    while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
        sk.advance_preparation();
        iterations += 1;
    }
    assert!(
        sk.get_prepared_interval().contains(&(epoch as u64)),
        "Failed to advance key preparation to epoch {epoch}"
    );
}

fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

/// Run a full keygen → sign → verify cycle for a single LeanSig
/// instantiation and print the results.
pub fn run_and_print<S: SignatureScheme>(name: &str) {
    let mut rng = rand::rng();
    let activation_epoch: usize = 0;
    let num_active_epochs = S::LIFETIME as usize;

    println!("=== {name} Benchmark ===\n");

    // --- Key Generation ---
    println!("--- Key Generation ---");
    let ((pk, mut sk), keygen_duration) =
        measure_time(|| S::key_gen(&mut rng, activation_epoch, num_active_epochs));
    print_timing("generate keys", keygen_duration);

    // Pick a low epoch so preparation is fast
    let epoch: u32 = 1;
    prepare_sk_for_epoch(&mut sk, epoch);

    // Use the canonical BENCH_MESSAGE (32 bytes = SHA-256 digest).
    // If MESSAGE_LENGTH differs from 32, we pad/truncate to fit.
    let mut message = [0u8; MESSAGE_LENGTH];
    let copy_len = BENCH_MESSAGE.len().min(MESSAGE_LENGTH);
    message[..copy_len].copy_from_slice(&BENCH_MESSAGE[..copy_len]);

    // --- Signing ---
    println!("\n--- Signing ---");
    let (sig_result, sign_duration) = measure_time(|| S::sign(&sk, epoch, &message));
    print_timing("sign", sign_duration);
    let sig = sig_result.expect("signing should succeed");

    // --- Verification ---
    println!("\n--- Verification ---");
    let (is_valid, verify_duration) = measure_time(|| S::verify(&pk, epoch, &message, &sig));
    print_timing("verify", verify_duration);

    if is_valid {
        println!("Signature verification: SUCCESS");
    } else {
        println!("Signature verification: FAILED");
    }

    // --- Sizes (SSZ serialized) ---
    let pk_bytes = pk.to_bytes().len();
    let sk_bytes = sk.to_bytes().len();
    let sig_bytes = sig.to_bytes().len();

    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", pk_bytes);
    println!("Secret key size: {} bytes", sk_bytes);
    println!("Signature size:  {} bytes", sig_bytes);

    println!("\n=== Summary ===");
    println!("Algorithm: {name}");
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
    println!("\nSizes (SSZ):");
    println!("  Public Key:  {} bytes", pk_bytes);
    println!("  Secret Key:  {} bytes", sk_bytes);
    println!("  Signature:   {} bytes", sig_bytes);
}
