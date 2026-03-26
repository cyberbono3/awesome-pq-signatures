use pq_bench::format_ns;

use crate::cli::CliConfig;
use crate::types::BenchResult;

pub fn print_table(results: &mut [BenchResult]) {
    results.sort_by_key(|result| result.sizes.signature_bytes);

    let algorithm_width = results
        .iter()
        .map(|result| result.algorithm.len())
        .max()
        .unwrap_or(9)
        .max(9);
    let param_width = results
        .iter()
        .map(|result| result.param_set.len())
        .max()
        .unwrap_or(9)
        .max(9);

    let separator = format!(
        "|-{:-<algorithm_width$}-|-{:-<param_width$}-|-{:-<12}-|-{:-<12}-|-{:-<12}-|-{:-<8}-|-{:-<8}-|-{:-<8}-|",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        algorithm_width = algorithm_width,
        param_width = param_width
    );
    let header = format!(
        "| {:<algorithm_width$} | {:<param_width$} | {:>12} | {:>12} | {:>12} | {:>8} | {:>8} | {:>8} |",
        "Algorithm",
        "Param Set",
        "Keygen",
        "Sign",
        "Verify",
        "PK (B)",
        "SK (B)",
        "Sig (B)",
        algorithm_width = algorithm_width,
        param_width = param_width
    );

    println!("\n{separator}\n{header}\n{separator}");
    for result in results {
        println!(
            "| {:<algorithm_width$} | {:<param_width$} | {:>12} | {:>12} | {:>12} | {:>8} | {:>8} | {:>8} |",
            result.algorithm,
            result.param_set,
            format_ns(result.keygen_median_ns),
            format_ns(result.sign_median_ns),
            format_ns(result.verify_median_ns),
            result.sizes.public_key_bytes,
            result.sizes.secret_key_bytes,
            result.sizes.signature_bytes,
            algorithm_width = algorithm_width,
            param_width = param_width
        );
    }
    println!("{separator}");
}

pub fn print_banner(total: usize, config: &CliConfig) {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  PQ Signature Benchmark Runner                       ║");
    println!(
        "║  {total} algorithms × {} run{} @ {} byte message{:>8}║",
        config.runs,
        if config.runs == 1 { "" } else { "s" },
        config.message_size,
        ""
    );
    println!("╚══════════════════════════════════════════════════════╝\n");
}
