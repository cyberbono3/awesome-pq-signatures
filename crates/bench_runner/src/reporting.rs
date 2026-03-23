use std::fs;
use std::path::Path;

use pq_bench::format_ns;

use crate::cli::CliConfig;
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

pub struct CsvReporter {
    writer: csv::Writer<std::fs::File>,
}

impl CsvReporter {
    pub fn new(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(path)?;
        let mut reporter = Self {
            writer: csv::Writer::from_writer(file),
        };
        reporter
            .writer
            .write_record([
                "algorithm",
                "param_set",
                "keygen_median_ns",
                "sign_median_ns",
                "verify_median_ns",
                "public_key_bytes",
                "secret_key_bytes",
                "signature_bytes",
            ])
            .map_err(std::io::Error::other)?;
        reporter.writer.flush()?;
        Ok(reporter)
    }

    pub fn write_result(&mut self, result: &BenchResult) -> csv::Result<()> {
        self.writer.write_record([
            result.algorithm.as_str(),
            result.param_set.as_str(),
            &result.keygen_median_ns.to_string(),
            &result.sign_median_ns.to_string(),
            &result.verify_median_ns.to_string(),
            &result.sizes.public_key_bytes.to_string(),
            &result.sizes.secret_key_bytes.to_string(),
            &result.sizes.signature_bytes.to_string(),
        ])?;
        self.writer.flush()?;
        Ok(())
    }
}

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
