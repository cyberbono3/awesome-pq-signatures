use lamport_ots::{seed_from_str, LamportOtsScheme, XorShift64};
use std::env;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message_size = parse_usize_env("LAMPORT_MESSAGE_SIZE", 1024)?;
    let iterations = parse_usize_env("LAMPORT_ITERATIONS", 100)?;
    let deterministic = parse_bool_env("LAMPORT_DETERMINISTIC", true);

    let scheme = LamportOtsScheme;
    let sizes = scheme.sizes();

    println!("algorithm: {}", scheme.algorithm_name());
    println!("backend: {}", scheme.backend_name());
    println!("param_set: {}", scheme.param_set_name());
    println!("public_key_bytes: {}", sizes.public_key_bytes);
    println!("secret_key_bytes: {}", sizes.secret_key_bytes);
    println!("signature_bytes: {}", sizes.signature_bytes);
    println!("message_size: {}", message_size);
    println!("iterations: {}", iterations);
    println!("deterministic_rng: {}", deterministic);

    let mut message = vec![0_u8; message_size];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }

    let keygen_elapsed = bench_keygen(scheme, iterations, deterministic)?;
    print_stats("keygen", iterations, keygen_elapsed.as_nanos());

    let sign_elapsed = bench_sign(scheme, &message, iterations, deterministic)?;
    print_stats("sign", iterations, sign_elapsed.as_nanos());

    let verify_elapsed =
        bench_verify(scheme, &message, iterations, deterministic)?;
    print_stats("verify", iterations, verify_elapsed.as_nanos());

    Ok(())
}

fn bench_keygen(
    scheme: LamportOtsScheme,
    iterations: usize,
    deterministic: bool,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let mut rng = bench_rng("keygen", deterministic);
    let start = Instant::now();
    for _ in 0..iterations {
        let keypair = scheme.keypair_with_rng(&mut rng);
        std::hint::black_box(keypair);
    }
    Ok(start.elapsed())
}

fn bench_sign(
    scheme: LamportOtsScheme,
    message: &[u8],
    iterations: usize,
    deterministic: bool,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let mut rng = bench_rng("sign-keygen", deterministic);
    let mut secret_keys = Vec::with_capacity(iterations.max(1));
    for _ in 0..iterations.max(1) {
        let (_, secret_key) = scheme.keypair_with_rng(&mut rng);
        secret_keys.push(secret_key);
    }

    let start = Instant::now();
    for secret_key in secret_keys.iter_mut().take(iterations) {
        let signature = scheme.sign(message, secret_key)?;
        std::hint::black_box(signature);
    }
    Ok(start.elapsed())
}

fn bench_verify(
    scheme: LamportOtsScheme,
    message: &[u8],
    iterations: usize,
    deterministic: bool,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let mut rng = bench_rng("verify-keygen", deterministic);
    let (public_key, mut secret_key) = scheme.keypair_with_rng(&mut rng);
    let signature = scheme.sign(message, &mut secret_key)?;

    let start = Instant::now();
    for _ in 0..iterations {
        let is_valid = scheme.verify(message, &signature, &public_key)?;
        if !is_valid {
            return Err("lamport verify failed during benchmark loop".into());
        }
        std::hint::black_box(is_valid);
    }
    Ok(start.elapsed())
}

fn print_stats(operation: &str, iterations: usize, total_ns: u128) {
    let avg_ns = if iterations == 0 {
        0
    } else {
        total_ns / iterations as u128
    };

    let throughput = if total_ns == 0 {
        0.0
    } else {
        (iterations as f64 * 1_000_000_000.0) / total_ns as f64
    };

    println!("{operation}_total_ns: {total_ns}");
    println!("{operation}_avg_ns: {avg_ns}");
    println!("{operation}_throughput_ops_per_s: {:.3}", throughput);
}

fn bench_rng(label: &str, deterministic: bool) -> XorShift64 {
    if deterministic {
        XorShift64::new(seed_from_str(&format!("lamport-main-{label}")))
    } else {
        XorShift64::new(random_seed(label))
    }
}

fn random_seed(label: &str) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id() as u64;
    let mix = now.as_nanos() as u64 ^ (pid << 32);
    mix ^ seed_from_str(label)
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
