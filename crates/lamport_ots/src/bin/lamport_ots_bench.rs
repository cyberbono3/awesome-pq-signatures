use lamport_ots::{benchmark_operation, LamportBenchOperation, BENCH_MESSAGE};
use pq_bench::{parse_bool_env, parse_usize_env, BenchmarkOperation};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation = env::var("OPERATION")
        .unwrap_or_else(|_| "keygen".to_owned())
        .parse::<BenchmarkOperation>()?;
    let iterations = parse_usize_env("ITERATIONS", 100)?;
    let deterministic = parse_bool_env("DETERMINISTIC_RNG", true);

    let message: &[u8] = &BENCH_MESSAGE;
    let operation = match operation {
        BenchmarkOperation::Keygen => LamportBenchOperation::Keygen,
        BenchmarkOperation::Sign => LamportBenchOperation::Sign,
        BenchmarkOperation::Verify => LamportBenchOperation::Verify,
    };
    let total =
        benchmark_operation(operation, message, iterations, deterministic)?;

    println!("{}", total.as_nanos());
    Ok(())
}
