use lamport_ots::{benchmark_operation, LamportBenchOperation, BENCH_MESSAGE};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation =
        env::var("OPERATION").unwrap_or_else(|_| "keygen".to_owned());
    let iterations = parse_usize_env("ITERATIONS", 100)?;
    let deterministic = parse_bool_env("DETERMINISTIC_RNG", true);

    let message: &[u8] = &BENCH_MESSAGE;
    let operation = match operation.as_str() {
        "keygen" => LamportBenchOperation::Keygen,
        "sign" => LamportBenchOperation::Sign,
        "verify" => LamportBenchOperation::Verify,
        other => {
            return Err(format!(
                "unsupported OPERATION={other}; expected one of: keygen, sign, verify"
            )
            .into())
        }
    };
    let total =
        benchmark_operation(operation, message, iterations, deterministic)?;

    println!("{}", total.as_nanos());
    Ok(())
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
