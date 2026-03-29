use std::env;

use pq_bench::{parse_usize_env, BenchmarkOperation};
use xmss_bench::{XmssParamSet, XmssScheme, BENCH_MESSAGE};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation = env::var("OPERATION")
        .unwrap_or_else(|_| "keygen".to_owned())
        .parse::<BenchmarkOperation>()?;
    let param_set = env::var("PARAM_SET")
        .unwrap_or_else(|_| "XMSS-SHA2_10_256".to_owned())
        .parse::<XmssParamSet>()?;
    let iterations = parse_usize_env("ITERATIONS", 100)?;

    let scheme = XmssScheme::new(param_set);
    let message: &[u8] = &BENCH_MESSAGE;
    let total = scheme.benchmark_operation(operation, message, iterations)?;

    println!("{}", total.as_nanos());
    Ok(())
}
