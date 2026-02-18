use std::env;
use std::time::Instant;

use xmss::{XmssParamSet, XmssScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let param_set = env::var("XMSS_PARAM_SET")
        .unwrap_or_else(|_| "XMSS-SHA2_10_256".to_owned())
        .parse::<XmssParamSet>()?;
    let message_size = parse_usize_env("XMSS_MESSAGE_SIZE", 1024)?;
    let iterations = parse_usize_env("XMSS_ITERATIONS", 100)?;

    let scheme = XmssScheme::new(param_set);
    let sizes = scheme.sizes()?;

    println!("algorithm: {}", scheme.algorithm_name());
    println!("backend: {}", scheme.backend_name());
    println!("param_set: {}", scheme.param_set().as_str());
    println!("public_key_bytes: {}", sizes.public_key_bytes);
    println!("secret_key_bytes: {}", sizes.secret_key_bytes);
    println!("signature_bytes: {}", sizes.signature_bytes);
    println!("message_size: {}", message_size);
    println!("iterations: {}", iterations);

    let message = vec![0x5A; message_size];

    let keygen_elapsed = bench_keygen(scheme, iterations)?;
    print_stats("keygen", iterations, keygen_elapsed.as_nanos());

    let sign_elapsed = bench_sign(scheme, &message, iterations)?;
    print_stats("sign", iterations, sign_elapsed.as_nanos());

    let verify_elapsed = bench_verify(scheme, &message, iterations)?;
    print_stats("verify", iterations, verify_elapsed.as_nanos());

    Ok(())
}

fn bench_keygen(
    scheme: XmssScheme,
    iterations: usize,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();
    for _ in 0..iterations {
        let keypair = scheme.keypair()?;
        std::hint::black_box(keypair);
    }
    Ok(start.elapsed())
}

fn bench_sign(
    scheme: XmssScheme,
    message: &[u8],
    iterations: usize,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let max_signatures = scheme.max_signatures_per_key()? as usize;
    let key_count = iterations.max(1).div_ceil(max_signatures.max(1));

    let mut secret_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let (_, secret_key) = scheme.keypair()?;
        secret_keys.push(secret_key);
    }

    let start = Instant::now();
    for i in 0..iterations {
        let key_index = i / max_signatures.max(1);
        let signature = scheme.sign(message, &mut secret_keys[key_index])?;
        std::hint::black_box(signature);
    }
    Ok(start.elapsed())
}

fn bench_verify(
    scheme: XmssScheme,
    message: &[u8],
    iterations: usize,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let (public_key, mut secret_key) = scheme.keypair()?;
    let signature = scheme.sign(message, &mut secret_key)?;

    let start = Instant::now();
    for _ in 0..iterations {
        let is_valid = scheme.verify(message, &signature, &public_key)?;
        if !is_valid {
            return Err("xmss verification failed during benchmark loop".into());
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

fn parse_usize_env(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}
