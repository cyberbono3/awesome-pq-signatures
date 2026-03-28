use crate::adapters::RunnerContext;
use crate::cli::{print_help, CliAction, CliConfig};
use crate::registry::{
    instantiate_adapters, resolve_binary_executables, selected_specs,
};
use crate::reporting::{print_banner, print_table, run_benchmark, CsvReporter};
use crate::types::{BenchResult, DsaBenchmark};
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
    run_with_adapters(&config, adapters)?;
    Ok(())
}

fn run_with_adapters(
    config: &CliConfig,
    adapters: Vec<Box<dyn DsaBenchmark>>,
) -> Result<Vec<BenchResult>, String> {
    let message = benchmark_message(config.message_size);
    let total = adapters.len();

    print_banner(total, config);

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

    Ok(results)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BenchRun, SizeMetrics};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct MockAdapter {
        name: &'static str,
        param_set: &'static str,
        runs: Mutex<VecDeque<Result<BenchRun, String>>>,
    }

    impl MockAdapter {
        fn new(
            name: &'static str,
            param_set: &'static str,
            runs: Vec<Result<BenchRun, String>>,
        ) -> Self {
            Self {
                name,
                param_set,
                runs: Mutex::new(runs.into()),
            }
        }
    }

    impl DsaBenchmark for MockAdapter {
        fn name(&self) -> &str {
            self.name
        }

        fn param_set(&self) -> &str {
            self.param_set
        }

        fn run_once(&self, _message: &[u8]) -> Result<BenchRun, String> {
            self.runs
                .lock()
                .expect("mock adapter mutex should not be poisoned")
                .pop_front()
                .expect("mock adapter should have a queued response")
        }
    }

    fn temp_csv_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bench_runner_app_{name}_{}_{}.csv",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ))
    }

    fn mock_run(keygen_ns: u64, sign_ns: u64, verify_ns: u64) -> BenchRun {
        BenchRun::from_durations(
            Duration::from_nanos(keygen_ns),
            Duration::from_nanos(sign_ns),
            Duration::from_nanos(verify_ns),
            SizeMetrics::new(11, 22, 33),
        )
    }

    #[test]
    fn run_with_adapters_writes_successful_results_to_csv() {
        let output = temp_csv_path("success");
        let mut config = CliConfig::default();
        config.output = output.clone();
        config.runs = 3;
        config.message_size = 64;

        let results = run_with_adapters(
            &config,
            vec![Box::new(MockAdapter::new(
                "Mock",
                "Mock-1",
                vec![
                    Ok(mock_run(10, 20, 30)),
                    Ok(mock_run(12, 18, 34)),
                    Ok(mock_run(11, 22, 32)),
                ],
            ))],
        )
        .expect("mock benchmark run should succeed");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].algorithm, "Mock");
        assert_eq!(results[0].param_set, "Mock-1");
        assert_eq!(results[0].keygen_median_ns, 11);
        assert_eq!(results[0].sign_median_ns, 20);
        assert_eq!(results[0].verify_median_ns, 32);

        let contents =
            std::fs::read_to_string(&output).expect("csv output should exist");
        assert!(contents.contains("Mock,Mock-1,11,20,32,11,22,33"));

        let _ = std::fs::remove_file(output);
    }

    #[test]
    fn run_with_adapters_keeps_successful_results_when_one_adapter_fails() {
        let output = temp_csv_path("partial");
        let mut config = CliConfig::default();
        config.output = output.clone();
        config.runs = 1;
        config.message_size = 32;

        let results = run_with_adapters(
            &config,
            vec![
                Box::new(MockAdapter::new(
                    "Good",
                    "Good-1",
                    vec![Ok(mock_run(5, 6, 7))],
                )),
                Box::new(MockAdapter::new(
                    "Bad",
                    "Bad-1",
                    vec![Err("boom".to_string())],
                )),
            ],
        )
        .expect("runner should continue after individual adapter failure");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].algorithm, "Good");

        let contents =
            std::fs::read_to_string(&output).expect("csv output should exist");
        assert!(contents.contains("Good,Good-1,5,6,7,11,22,33"));
        assert!(!contents.contains("Bad,Bad-1"));

        let _ = std::fs::remove_file(output);
    }
}
