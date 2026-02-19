use lm_ots::{
    bench_message, default_identifier, seed_bytes_from_u64, seed_from_str,
    LmOtsParamSet, LmOtsScheme, LMOTS_Q,
};
use std::env;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation =
        env::var("OPERATION").unwrap_or_else(|_| "keygen".to_owned());
    let param_set = parse_param_set_env("PARAM_SET")?;
    let iterations = parse_usize_env("ITERATIONS", 100)?;
    let message_size = parse_usize_env("MSG_SIZE", 32)?;
    let deterministic = parse_bool_env("DETERMINISTIC_RNG", true);

    let scheme = LmOtsScheme::new(param_set);
    let id = default_identifier();
    let message = bench_message(message_size);

    let total = match operation.as_str() {
        "keygen" => bench_keygen(scheme, id, iterations, deterministic)?,
        "sign" => bench_sign(
            scheme,
            id,
            &message,
            iterations,
            deterministic,
        )?,
        "verify" => bench_verify(
            scheme,
            id,
            &message,
            iterations,
            deterministic,
        )?,
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
    scheme: LmOtsScheme,
    id: [u8; 16],
    iterations: usize,
    deterministic: bool,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let seed_base = seed_from_str("lm-ots-bin-keygen");
    let start = Instant::now();
    for i in 0..iterations {
        let keypair = if deterministic {
            scheme.keypair_with_seed(
                LMOTS_Q,
                id,
                seed_bytes_from_u64(seed_base ^ i as u64),
            )
        } else {
            scheme.keypair(LMOTS_Q, id)
        };
        std::hint::black_box(keypair);
    }
    Ok(start.elapsed())
}

fn bench_sign(
    scheme: LmOtsScheme,
    id: [u8; 16],
    message: &[u8],
    iterations: usize,
    deterministic: bool,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let mut secret_keys = Vec::with_capacity(iterations.max(1));
    let key_seed_base = seed_from_str("lm-ots-bin-sign-keygen");
    for i in 0..iterations.max(1) {
        let (_pk, sk) = if deterministic {
            scheme.keypair_with_seed(
                LMOTS_Q,
                id,
                seed_bytes_from_u64(key_seed_base ^ i as u64),
            )
        } else {
            scheme.keypair(LMOTS_Q, id)
        };
        secret_keys.push(sk);
    }

    let sign_seed_base = seed_from_str("lm-ots-bin-sign");
    let start = Instant::now();
    for (i, secret_key) in secret_keys.iter_mut().take(iterations).enumerate() {
        let signature = if deterministic {
            scheme.sign_with_seed(
                message,
                secret_key,
                sign_seed_base ^ i as u64,
            )?
        } else {
            scheme.sign(message, secret_key)?
        };
        std::hint::black_box(signature);
    }
    Ok(start.elapsed())
}

fn bench_verify(
    scheme: LmOtsScheme,
    id: [u8; 16],
    message: &[u8],
    iterations: usize,
    deterministic: bool,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    let (public_key, mut secret_key) = if deterministic {
        scheme.keypair_with_seed(
            LMOTS_Q,
            id,
            seed_bytes_from_u64(seed_from_str("lm-ots-bin-verify-keygen")),
        )
    } else {
        scheme.keypair(LMOTS_Q, id)
    };
    let signature = if deterministic {
        scheme.sign_with_seed(
            message,
            &mut secret_key,
            seed_from_str("lm-ots-bin-verify-sign"),
        )?
    } else {
        scheme.sign(message, &mut secret_key)?
    };

    let start = Instant::now();
    for _ in 0..iterations {
        let valid = scheme.verify(message, &signature, &public_key)?;
        if !valid {
            return Err("lm-ots verify failed during benchmark loop".into());
        }
        std::hint::black_box(valid);
    }
    Ok(start.elapsed())
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
