mod adapters;
mod cli;
mod registry;
mod reporting;
mod types;

use adapters::RunnerContext;
use cli::{print_help, CliAction};
use pq_bench::benchmark_message;
use registry::{instantiate_adapters, resolve_ffi_binaries, selected_specs};
use reporting::{print_banner, print_table, run_benchmark, CsvReporter};

fn main() {
    let action = match CliAction::parse(std::env::args().skip(1)) {
        Ok(action) => action,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let config = match action {
        CliAction::Help => {
            print_help();
            return;
        }
        CliAction::Run(config) => config,
    };

    let specs = selected_specs(&config);
    if specs.is_empty() {
        eprintln!("no adapters matched the selected filters");
        std::process::exit(1);
    }

    let context = RunnerContext {
        message_size: config.message_size,
        ffi_executables: match resolve_ffi_binaries(&specs) {
            Ok(paths) => paths,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        },
    };
    let adapters = instantiate_adapters(&specs, &context);
    let message = benchmark_message(config.message_size);
    let total = adapters.len();

    print_banner(total, &config);

    let mut csv = match CsvReporter::new(&config.output) {
        Ok(csv) => csv,
        Err(err) => {
            eprintln!("failed to open CSV output: {err}");
            std::process::exit(1);
        }
    };

    let mut results = Vec::with_capacity(total);
    for (index, adapter) in adapters.iter().enumerate() {
        match run_benchmark(
            adapter.as_ref(),
            &message,
            config.runs,
            index,
            total,
        ) {
            Ok(result) => {
                if let Err(err) = csv.write_result(&result) {
                    eprintln!("  ! failed to write CSV row: {err}");
                }
                results.push(result);
            }
            Err(err) => {
                println!();
                eprintln!("  ✗ FAILED: {} — {}", adapter.name(), err);
            }
        }
    }

    print_table(&mut results);
    println!(
        "\nResults written to {} ({}/{} algorithms)",
        config.output.display(),
        results.len(),
        total
    );
}
