use pq_bench::format_ns;

use crate::types::{BenchResult, DsaBenchmark};

pub fn run_benchmark(
    adapter: &dyn DsaBenchmark,
    message: &[u8],
    runs: usize,
    index: usize,
    total: usize,
) -> Result<BenchResult, String> {
    print!(
        "[{}/{}] Benchmarking {} ({})... {} run{}",
        index + 1,
        total,
        adapter.name(),
        adapter.param_set(),
        runs,
        if runs == 1 { "" } else { "s" }
    );
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        samples.push(adapter.run_once(message)?);
    }

    let result = BenchResult::from_runs(adapter, &samples);
    print_benchmark_summary(&result);
    Ok(result)
}

fn print_benchmark_summary(result: &BenchResult) {
    println!();
    println!("  ✓ keygen: median {}", format_ns(result.keygen_median_ns));
    println!("  ✓ sign:   median {}", format_ns(result.sign_median_ns));
    println!("  ✓ verify: median {}", format_ns(result.verify_median_ns));
    println!(
        "  ✓ sizes:  pk={} sk={} sig={} bytes",
        result.sizes.public_key_bytes,
        result.sizes.secret_key_bytes,
        result.sizes.signature_bytes
    );
}
