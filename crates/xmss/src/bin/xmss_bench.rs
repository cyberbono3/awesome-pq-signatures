use std::env;
use std::time::Instant;

use xmss::{XmssParamSet, XmssScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation =
        env::var("OPERATION").unwrap_or_else(|_| "keygen".to_owned());
    let param_set = env::var("PARAM_SET")
        .unwrap_or_else(|_| "XMSS-SHA2_10_256".to_owned())
        .parse::<XmssParamSet>()?;
    let message_size = parse_usize_env("MSG_SIZE", 32)?;
    let iterations = parse_usize_env("ITERATIONS", 100)?;

    let scheme = XmssScheme::new(param_set);
    let message = vec![0xA5; message_size];

    let total = match operation.as_str() {
        "keygen" => bench_keygen(scheme, iterations)?,
        "sign" => bench_sign(scheme, &message, iterations)?,
        "verify" => bench_verify(scheme, &message, iterations)?,
        other => {
            return Err(format!(
                "unsupported OPERATION={other}; expected one of: keygen, sign, verify"
            )
            .into())
        }
    };

    println!("{}", total.as_nanos());
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

fn parse_usize_env(
    name: &str,
    default: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}
