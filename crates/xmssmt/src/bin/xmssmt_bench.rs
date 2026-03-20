use std::env;
use std::time::Instant;

use xmssmt_bench::{XmssmtParamSet, XmssmtScheme, BENCH_MESSAGE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation = env::var("OPERATION").unwrap_or_else(|_| "keygen".to_owned());
    let param_set = env::var("PARAM_SET")
        .unwrap_or_else(|_| "XMSSMT-SHA2_20/2_256".to_owned())
        .parse::<XmssmtParamSet>()?;
    let iterations = parse_usize_env("ITERATIONS", 100)?;

    let scheme = XmssmtScheme::new(param_set);
    let message: &[u8] = &BENCH_MESSAGE;

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
    scheme: XmssmtScheme,
    iterations: usize,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();
    for _ in 0..iterations {
        let kp = scheme.keypair()?;
        std::hint::black_box(kp);
    }
    Ok(start.elapsed())
}

fn bench_sign(
    scheme: XmssmtScheme,
    message: &[u8],
    iterations: usize,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let max_signatures = usize::try_from(scheme.max_signatures_per_key()?)?;
    let key_count = iterations.max(1).div_ceil(max_signatures.max(1));

    let mut keypairs = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        keypairs.push(scheme.keypair()?);
    }

    let start = Instant::now();
    for i in 0..iterations {
        let key_index = i / max_signatures.max(1);
        let signature = keypairs[key_index].sign(message)?;
        std::hint::black_box(signature);
    }
    Ok(start.elapsed())
}

fn bench_verify(
    scheme: XmssmtScheme,
    message: &[u8],
    iterations: usize,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let mut kp = scheme.keypair()?;
    let signature = kp.sign(message)?;

    let start = Instant::now();
    for _ in 0..iterations {
        let is_valid = kp.verify(message, &signature)?;
        if !is_valid {
            return Err("xmssmt verification failed during benchmark loop".into());
        }
        std::hint::black_box(is_valid);
    }
    Ok(start.elapsed())
}

fn parse_usize_env(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}
