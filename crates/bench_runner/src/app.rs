use crate::adapters::RunnerContext;
use crate::cli::{print_help, CliAction, CliConfig};
use crate::registry::{
    instantiate_adapters, resolve_binary_executables, selected_specs,
};
use crate::reporting::{print_banner, print_table, run_benchmark, CsvReporter};
use pq_bench::benchmark_message;

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    match CliAction::parse(args)? {
        CliAction::Help => {
            print_help();
            Ok(())
        }
        CliAction::Run(config) => run_with_config(config),
    }
}

fn run_with_config(config: CliConfig) -> Result<(), String> {
    let specs = selected_specs(&config);
    if specs.is_empty() {
        return Err("no adapters matched the selected filters".to_string());
    }

    let context = build_runner_context(&specs, config.message_size)?;
    let adapters = instantiate_adapters(&specs, &context);
    let message = benchmark_message(config.message_size);
    let total = adapters.len();

    print_banner(total, &config);

    let mut csv = CsvReporter::new(&config.output)
        .map_err(|err| format!("failed to open CSV output: {err}"))?;

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

    Ok(())
}

fn build_runner_context(
    specs: &[&'static crate::registry::AdapterSpec],
    message_size: usize,
) -> Result<RunnerContext, String> {
    Ok(RunnerContext {
        message_size,
        binary_executables: resolve_binary_executables(specs)?,
    })
}
