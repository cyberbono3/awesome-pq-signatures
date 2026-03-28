use std::env;

use pq_bench::{parse_usize_env, BenchmarkOperation};
use xmssmt_bench::{XmssmtParamSet, XmssmtScheme, BENCH_MESSAGE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation = env::var("OPERATION")
        .unwrap_or_else(|_| "keygen".to_owned())
        .parse::<BenchmarkOperation>()?;
    let param_set = env::var("PARAM_SET")
        .unwrap_or_else(|_| "XMSSMT-SHA2_20/2_256".to_owned())
        .parse::<XmssmtParamSet>()?;
    let iterations = parse_usize_env("ITERATIONS", 100)?;

    let scheme = XmssmtScheme::new(param_set);
    let message: &[u8] = &BENCH_MESSAGE;
    let total = scheme.benchmark_operation(operation, message, iterations)?;

    println!("{}", total.as_nanos());
    Ok(())
}
