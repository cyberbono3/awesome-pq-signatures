//! Unified benchmark runner for all PQ DSA crates.
//!
//! Pure-Rust crates are benchmarked in-process. FFI-based crates (CROSS,
//! SQISign, LESS) are run as separate subprocesses via their standalone
//! binaries to avoid C global-state conflicts.
//!
//! Usage:
//!   cargo run --release --bin bench_runner -- --runs 10
//!   make run RUNS=10

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use pq_bench::{format_ns, measure_time, median, BENCH_MESSAGE};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SizeMetrics {
    public_key_bytes: usize,
    secret_key_bytes: usize,
    signature_bytes: usize,
}

impl SizeMetrics {
    const fn new(
        public_key_bytes: usize,
        secret_key_bytes: usize,
        signature_bytes: usize,
    ) -> Self {
        Self {
            public_key_bytes,
            secret_key_bytes,
            signature_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BenchRun {
    keygen_ns: u128,
    sign_ns: u128,
    verify_ns: u128,
    sizes: SizeMetrics,
}

impl BenchRun {
    fn from_durations(
        keygen: Duration,
        sign: Duration,
        verify: Duration,
        sizes: SizeMetrics,
    ) -> Self {
        Self {
            keygen_ns: keygen.as_nanos(),
            sign_ns: sign.as_nanos(),
            verify_ns: verify.as_nanos(),
            sizes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BenchResult {
    algorithm: String,
    param_set: String,
    keygen_median_ns: u128,
    sign_median_ns: u128,
    verify_median_ns: u128,
    sizes: SizeMetrics,
}

impl BenchResult {
    fn from_runs(adapter: &dyn DsaBenchmark, runs: &[BenchRun]) -> Self {
        let mut keygen_samples: Vec<_> =
            runs.iter().map(|run| run.keygen_ns).collect();
        let mut sign_samples: Vec<_> =
            runs.iter().map(|run| run.sign_ns).collect();
        let mut verify_samples: Vec<_> =
            runs.iter().map(|run| run.verify_ns).collect();

        Self {
            algorithm: adapter.name().to_string(),
            param_set: adapter.param_set().to_string(),
            keygen_median_ns: median(&mut keygen_samples),
            sign_median_ns: median(&mut sign_samples),
            verify_median_ns: median(&mut verify_samples),
            sizes: runs.first().map(|run| run.sizes).unwrap_or_default(),
        }
    }
}

trait DsaBenchmark {
    fn name(&self) -> &str;
    fn param_set(&self) -> &str;
    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String>;
}

struct DilithiumAdapter;

impl DsaBenchmark for DilithiumAdapter {
    fn name(&self) -> &str {
        "ML-DSA-65 (Dilithium)"
    }

    fn param_set(&self) -> &str {
        "ML-DSA-65"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use dilithium::{default_seed, SignatureScheme as _, ML_DSA_65};

        let seed = default_seed();
        let (keypair, keygen_duration) =
            measure_time(|| ML_DSA_65.keypair(&seed));
        let (signature, sign_duration) = measure_time(|| {
            ML_DSA_65.sign(&keypair, message, &[]).expect("sign")
        });
        let (_, verify_duration) = measure_time(|| {
            ML_DSA_65.verify(&keypair, message, &[], &signature)
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                ML_DSA_65.public_key_size(&keypair),
                ML_DSA_65.secret_key_size(&keypair),
                ML_DSA_65.signature_size(&signature),
            ),
        ))
    }
}

struct FalconAdapter;

impl DsaBenchmark for FalconAdapter {
    fn name(&self) -> &str {
        "Falcon-512"
    }

    fn param_set(&self) -> &str {
        "Falcon-512"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use falcon::{signature_size, SignatureScheme as _, FALCON512};
        use pqcrypto_traits::sign::{PublicKey, SecretKey};

        let ((public_key, secret_key), keygen_duration) =
            measure_time(|| FALCON512.keypair());
        let (signed_message, sign_duration) =
            measure_time(|| FALCON512.sign(message, &secret_key));
        let (_, verify_duration) =
            measure_time(|| FALCON512.open(&signed_message, &public_key));

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                public_key.as_bytes().len(),
                secret_key.as_bytes().len(),
                signature_size(&signed_message, message.len()),
            ),
        ))
    }
}

struct SphincsPlusAdapter;

impl DsaBenchmark for SphincsPlusAdapter {
    fn name(&self) -> &str {
        "SPHINCS+-SHAKE-128f"
    }

    fn param_set(&self) -> &str {
        "SPHINCS+-SHAKE-128f-simple"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use pqcrypto_traits::sign::{PublicKey, SecretKey};
        use sphincs_plus::{
            signature_size, SignatureScheme as _,
            SPHINCS_PLUS_SHAKE_128F_SIMPLE,
        };

        let ((public_key, secret_key), keygen_duration) =
            measure_time(|| SPHINCS_PLUS_SHAKE_128F_SIMPLE.keypair());
        let (signed_message, sign_duration) = measure_time(|| {
            SPHINCS_PLUS_SHAKE_128F_SIMPLE.sign(message, &secret_key)
        });
        let (_, verify_duration) = measure_time(|| {
            SPHINCS_PLUS_SHAKE_128F_SIMPLE.open(&signed_message, &public_key)
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                public_key.as_bytes().len(),
                secret_key.as_bytes().len(),
                signature_size(&signed_message, message.len()),
            ),
        ))
    }
}

struct MayoAdapter;

impl DsaBenchmark for MayoAdapter {
    fn name(&self) -> &str {
        "MAYO-1"
    }

    fn param_set(&self) -> &str {
        "MAYO-1"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use mayo::MAYO;

        let (keypair, keygen_duration) =
            measure_time(|| MAYO.benchmark_keypair());
        let (signature, sign_duration) = measure_time(|| {
            MAYO.sign_message(&keypair, message).expect("sign")
        });
        let (_, verify_duration) =
            measure_time(|| MAYO.verify_message(&keypair, message, &signature));
        let sizes = MAYO.sizes(&keypair, &signature);

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                sizes.public_key_bytes,
                sizes.secret_key_bytes,
                sizes.signature_bytes,
            ),
        ))
    }
}

struct LmsAdapter;

impl DsaBenchmark for LmsAdapter {
    fn name(&self) -> &str {
        "LMS"
    }

    fn param_set(&self) -> &str {
        "LMS-SHA256-M32-H5"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use lms::{default_seed, LmsScheme, DEFAULT_PARAM_SET_NAME};

        let scheme = LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .map_err(|err| format!("{err:?}"))?;
        let ((public_key, mut secret_key), keygen_duration) =
            measure_time(|| {
                scheme.keypair_with_seed(default_seed()).expect("kg")
            });
        let (signature, sign_duration) = measure_time(|| {
            scheme.sign(message, &mut secret_key).expect("sign")
        });
        let (_, verify_duration) = measure_time(|| {
            scheme
                .verify(message, &signature, &public_key)
                .expect("verify")
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                scheme.public_key_size(&public_key),
                scheme.secret_key_size(&secret_key),
                scheme.signature_size(&signature),
            ),
        ))
    }
}

struct HssAdapter;

impl DsaBenchmark for HssAdapter {
    fn name(&self) -> &str {
        "HSS"
    }

    fn param_set(&self) -> &str {
        "HSS-SHA256-H5-W2-L1"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use hss::{default_seed, HssScheme, DEFAULT_PARAM_SET_NAME};

        let scheme = HssScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .map_err(|err| format!("{err:?}"))?;
        let ((public_key, mut secret_key), keygen_duration) =
            measure_time(|| {
                scheme.keypair_with_seed(default_seed()).expect("kg")
            });
        let (signature, sign_duration) = measure_time(|| {
            scheme.sign(message, &mut secret_key).expect("sign")
        });
        let (_, verify_duration) = measure_time(|| {
            scheme
                .verify(message, &signature, &public_key)
                .expect("verify")
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                scheme.public_key_size(&public_key),
                scheme.secret_key_size(&secret_key),
                scheme.signature_size(&signature),
            ),
        ))
    }
}

struct XmssAdapter;

impl DsaBenchmark for XmssAdapter {
    fn name(&self) -> &str {
        "XMSS"
    }

    fn param_set(&self) -> &str {
        "XMSS-SHA2_10_256"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        let scheme = xmss_bench::default_benchmark_scheme();
        let ((public_key, mut secret_key), keygen_duration) =
            measure_time(|| scheme.keypair().expect("kg"));
        let (signature, sign_duration) = measure_time(|| {
            scheme.sign(message, &mut secret_key).expect("sign")
        });
        let (_, verify_duration) = measure_time(|| {
            scheme
                .verify(message, &signature, &public_key)
                .expect("verify")
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                public_key.len(),
                secret_key.len(),
                signature.len(),
            ),
        ))
    }
}

struct XmssmtAdapter;

impl DsaBenchmark for XmssmtAdapter {
    fn name(&self) -> &str {
        "XMSS^MT"
    }

    fn param_set(&self) -> &str {
        "XMSSMT-SHA2_20/2_256"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        let scheme = xmssmt_bench::default_benchmark_scheme();
        let (mut keypair, keygen_duration) =
            measure_time(|| scheme.keypair().expect("kg"));
        let sizes = SizeMetrics::new(
            keypair.public_key_len(),
            keypair.secret_key_len(),
            0,
        );
        let (signature, sign_duration) =
            measure_time(|| keypair.sign(message).expect("sign"));
        let (_, verify_duration) = measure_time(|| {
            keypair.verify(message, &signature).expect("verify")
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                sizes.public_key_bytes,
                sizes.secret_key_bytes,
                signature.len(),
            ),
        ))
    }
}

struct LeansigAdapter;

impl DsaBenchmark for LeansigAdapter {
    fn name(&self) -> &str {
        "LeanSig"
    }

    fn param_set(&self) -> &str {
        "Poseidon-L2^18-TS-w4"
    }

    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String> {
        use leansig::serialization::Serializable;
        use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W4NoOff;
        use leansig::signature::SignatureScheme;
        use leansig::MESSAGE_LENGTH;
        use leansig_bench::prepare_sk_for_epoch;

        type Scheme = SIGTargetSumLifetime18W4NoOff;

        let message = copy_into_fixed::<MESSAGE_LENGTH>(message);
        let mut rng = rand::rng();
        let ((public_key, mut secret_key), keygen_duration) =
            measure_time(|| {
                Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize)
            });
        prepare_sk_for_epoch(&mut secret_key, 1);
        let (signature, sign_duration) = measure_time(|| {
            Scheme::sign(&secret_key, 1, &message).expect("sign")
        });
        let (_, verify_duration) = measure_time(|| {
            Scheme::verify(&public_key, 1, &message, &signature)
        });

        Ok(BenchRun::from_durations(
            keygen_duration,
            sign_duration,
            verify_duration,
            SizeMetrics::new(
                public_key.to_bytes().len(),
                secret_key.to_bytes().len(),
                signature.to_bytes().len(),
            ),
        ))
    }
}

struct SubprocessAdapter {
    algorithm: &'static str,
    param_set: &'static str,
    binary: &'static str,
}

impl DsaBenchmark for SubprocessAdapter {
    fn name(&self) -> &str {
        self.algorithm
    }

    fn param_set(&self) -> &str {
        self.param_set
    }

    fn run_once(&self, _message: &[u8]) -> Result<BenchRun, String> {
        let output = Command::new("cargo")
            .args(["run", "--release", "--bin", self.binary])
            .output()
            .map_err(|err| format!("spawn failed: {err}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "exit {}: {}",
                output.status,
                stderr.lines().last().unwrap_or("")
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_binary_output(&stdout)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliConfig {
    runs: usize,
    output: PathBuf,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            runs: 10,
            output: PathBuf::from("benchmarks/results.csv"),
        }
    }
}

#[derive(Debug)]
enum CliAction {
    Help,
    Run(CliConfig),
}

impl CliAction {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut config = CliConfig::default();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--runs" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--runs requires a value".to_string())?;
                    config.runs = value
                        .parse()
                        .map_err(|_| format!("invalid runs value: {value}"))?;
                    if config.runs == 0 {
                        return Err("--runs must be greater than 0".to_string());
                    }
                }
                "--output" => {
                    let value = args.next().ok_or_else(|| {
                        "--output requires a value".to_string()
                    })?;
                    config.output = PathBuf::from(value);
                }
                "--help" | "-h" => return Ok(Self::Help),
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        Ok(Self::Run(config))
    }
}

fn copy_into_fixed<const N: usize>(message: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let len = message.len().min(N);
    output[..len].copy_from_slice(&message[..len]);
    output
}

fn parse_binary_output(stdout: &str) -> Result<BenchRun, String> {
    let keygen_ns = parse_ns(stdout, "generate keys")
        .ok_or_else(|| "missing keygen timing".to_string())?;
    let sign_ns = parse_ns(stdout, "sign")
        .ok_or_else(|| "missing sign timing".to_string())?;
    let verify_ns = parse_ns(stdout, "verify")
        .ok_or_else(|| "missing verify timing".to_string())?;
    let sizes = SizeMetrics::new(
        parse_bytes(stdout, "Public key size")
            .ok_or_else(|| "missing pk size".to_string())?,
        parse_bytes(stdout, "Secret key size")
            .ok_or_else(|| "missing sk size".to_string())?,
        parse_bytes(stdout, "Signature size")
            .ok_or_else(|| "missing sig size".to_string())?,
    );

    Ok(BenchRun {
        keygen_ns,
        sign_ns,
        verify_ns,
        sizes,
    })
}

fn parse_ns(stdout: &str, label: &str) -> Option<u128> {
    extract_field(stdout, label, "(ns)")?.parse().ok()
}

fn parse_bytes(stdout: &str, label: &str) -> Option<usize> {
    extract_field(stdout, label, "bytes")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn extract_field<'a>(
    stdout: &'a str,
    label: &str,
    suffix: &str,
) -> Option<&'a str> {
    stdout
        .lines()
        .find(|line| line.contains(label) && line.contains(suffix))?
        .split(':')
        .last()
        .map(str::trim)
}

fn run_benchmark(
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
    std::io::stdout().flush().ok();

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

fn write_csv(results: &[BenchResult], path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(path)?;
    writeln!(
        file,
        "algorithm,param_set,keygen_median_ns,sign_median_ns,verify_median_ns,public_key_bytes,secret_key_bytes,signature_bytes"
    )?;

    for result in results {
        writeln!(
            file,
            "{},{},{},{},{},{},{},{}",
            result.algorithm,
            result.param_set,
            result.keygen_median_ns,
            result.sign_median_ns,
            result.verify_median_ns,
            result.sizes.public_key_bytes,
            result.sizes.secret_key_bytes,
            result.sizes.signature_bytes
        )?;
    }

    Ok(())
}

fn print_table(results: &mut [BenchResult]) {
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

fn benchmark_adapters() -> Vec<Box<dyn DsaBenchmark>> {
    vec![
        Box::new(DilithiumAdapter),
        Box::new(FalconAdapter),
        Box::new(SphincsPlusAdapter),
        Box::new(MayoAdapter),
        Box::new(LmsAdapter),
        Box::new(HssAdapter),
        Box::new(XmssAdapter),
        Box::new(XmssmtAdapter),
        Box::new(LeansigAdapter),
        Box::new(SubprocessAdapter {
            algorithm: "SQISign",
            param_set: "SQISign-lvl1",
            binary: "sqisign",
        }),
        Box::new(SubprocessAdapter {
            algorithm: "LESS",
            param_set: "LESS-252-45",
            binary: "less",
        }),
        Box::new(SubprocessAdapter {
            algorithm: "CROSS",
            param_set: "CROSS-RSDPG-192-BAL",
            binary: "cross",
        }),
    ]
}

fn print_banner(total: usize, runs: usize) {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  PQ Signature Benchmark Runner                       ║");
    println!(
        "║  {total} algorithms × {runs} run{}                          ║",
        if runs == 1 { "" } else { "s" }
    );
    println!("╚══════════════════════════════════════════════════════╝\n");
}

fn print_help() {
    println!("Usage: bench_runner [--runs N] [--output PATH]");
}

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

    let message: &[u8] = &BENCH_MESSAGE;
    let adapters = benchmark_adapters();
    let total = adapters.len();

    print_banner(total, config.runs);

    let mut results = Vec::with_capacity(total);
    for (index, adapter) in adapters.iter().enumerate() {
        match run_benchmark(
            adapter.as_ref(),
            message,
            config.runs,
            index,
            total,
        ) {
            Ok(result) => {
                results.push(result);
                if let Err(err) = write_csv(&results, &config.output) {
                    eprintln!("  ! failed to write CSV: {err}");
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_action_parses_config() {
        let action = CliAction::parse([
            "--runs".to_string(),
            "7".to_string(),
            "--output".to_string(),
            "out/results.csv".to_string(),
        ])
        .expect("config should parse");

        match action {
            CliAction::Run(config) => {
                assert_eq!(config.runs, 7);
                assert_eq!(config.output, PathBuf::from("out/results.csv"));
            }
            CliAction::Help => panic!("expected run config"),
        }
    }

    #[test]
    fn cli_action_rejects_zero_runs() {
        let err = CliAction::parse(["--runs".to_string(), "0".to_string()])
            .expect_err("zero runs should be rejected");
        assert_eq!(err, "--runs must be greater than 0");
    }

    #[test]
    fn parse_binary_output_extracts_metrics() {
        let run = parse_binary_output(
            "Time to generate keys (ns): 10\n\
             Time to sign (ns): 20\n\
             Time to verify (ns): 30\n\
             Public key size: 40 bytes\n\
             Secret key size: 50 bytes\n\
             Signature size: 60 bytes\n",
        )
        .expect("output should parse");

        assert_eq!(
            run,
            BenchRun {
                keygen_ns: 10,
                sign_ns: 20,
                verify_ns: 30,
                sizes: SizeMetrics::new(40, 50, 60),
            }
        );
    }
}
