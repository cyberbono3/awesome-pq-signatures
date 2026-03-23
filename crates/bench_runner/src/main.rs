//! Unified benchmark runner for all PQ DSA crates.
//!
//! Pure-Rust crates are benchmarked in-process. FFI-based crates (CROSS,
//! SQISign, LESS) are built once and then executed as standalone release
//! binaries with machine-readable JSON output.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use pq_bench::{
    benchmark_message, format_ns, measure_time, median, BenchmarkBinaryReport,
    BENCH_MESSAGE,
};

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

    fn from_binary_report(report: &BenchmarkBinaryReport) -> Self {
        Self {
            keygen_ns: u128::from(report.keygen_ns),
            sign_ns: u128::from(report.sign_ns),
            verify_ns: u128::from(report.verify_ns),
            sizes: SizeMetrics::new(
                report.sizes.public_key_bytes,
                report.sizes.secret_key_bytes,
                report.sizes.signature_bytes,
            ),
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

fn measure_benchmark_flow<K, S>(
    keygen: impl FnOnce() -> K,
    sign: impl FnOnce(&mut K) -> S,
    verify: impl FnOnce(&K, &S),
    sizes: impl FnOnce(&K, &S) -> SizeMetrics,
) -> BenchRun {
    let (mut key_material, keygen_duration) = measure_time(keygen);
    let (signature, sign_duration) = measure_time(|| sign(&mut key_material));
    let (_, verify_duration) =
        measure_time(|| verify(&key_material, &signature));
    BenchRun::from_durations(
        keygen_duration,
        sign_duration,
        verify_duration,
        sizes(&key_material, &signature),
    )
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
        Ok(measure_benchmark_flow(
            || ML_DSA_65.keypair(&seed),
            |keypair| ML_DSA_65.sign(keypair, message, &[]).expect("sign"),
            |keypair, signature| {
                ML_DSA_65.verify(keypair, message, &[], signature);
            },
            |keypair, signature| {
                SizeMetrics::new(
                    ML_DSA_65.public_key_size(keypair),
                    ML_DSA_65.secret_key_size(keypair),
                    ML_DSA_65.signature_size(signature),
                )
            },
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

        Ok(measure_benchmark_flow(
            || FALCON512.keypair(),
            |(_, secret_key)| FALCON512.sign(message, secret_key),
            |(public_key, _), signed_message| {
                FALCON512.open(signed_message, public_key);
            },
            |(public_key, secret_key), signed_message| {
                SizeMetrics::new(
                    public_key.as_bytes().len(),
                    secret_key.as_bytes().len(),
                    signature_size(signed_message, message.len()),
                )
            },
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

        Ok(measure_benchmark_flow(
            || SPHINCS_PLUS_SHAKE_128F_SIMPLE.keypair(),
            |(_, secret_key)| {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE.sign(message, secret_key)
            },
            |(public_key, _), signed_message| {
                SPHINCS_PLUS_SHAKE_128F_SIMPLE.open(signed_message, public_key);
            },
            |(public_key, secret_key), signed_message| {
                SizeMetrics::new(
                    public_key.as_bytes().len(),
                    secret_key.as_bytes().len(),
                    signature_size(signed_message, message.len()),
                )
            },
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

        Ok(measure_benchmark_flow(
            || MAYO.benchmark_keypair(),
            |keypair| MAYO.sign_message(keypair, message).expect("sign"),
            |keypair, signature| {
                MAYO.verify_message(keypair, message, signature);
            },
            |keypair, signature| {
                let sizes = MAYO.sizes(keypair, signature);
                SizeMetrics::new(
                    sizes.public_key_bytes,
                    sizes.secret_key_bytes,
                    sizes.signature_bytes,
                )
            },
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
        Ok(measure_benchmark_flow(
            || scheme.keypair_with_seed(default_seed()).expect("kg"),
            |(_, secret_key)| scheme.sign(message, secret_key).expect("sign"),
            |(public_key, _), signature| {
                scheme
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    scheme.public_key_size(public_key),
                    scheme.secret_key_size(secret_key),
                    scheme.signature_size(signature),
                )
            },
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
        Ok(measure_benchmark_flow(
            || scheme.keypair_with_seed(default_seed()).expect("kg"),
            |(_, secret_key)| scheme.sign(message, secret_key).expect("sign"),
            |(public_key, _), signature| {
                scheme
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    scheme.public_key_size(public_key),
                    scheme.secret_key_size(secret_key),
                    scheme.signature_size(signature),
                )
            },
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
        Ok(measure_benchmark_flow(
            || scheme.keypair().expect("kg"),
            |(_, secret_key)| scheme.sign(message, secret_key).expect("sign"),
            |(public_key, _), signature| {
                scheme
                    .verify(message, signature, public_key)
                    .expect("verify");
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    public_key.len(),
                    secret_key.len(),
                    signature.len(),
                )
            },
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
        Ok(measure_benchmark_flow(
            || {
                let mut keypair = scheme.keypair().expect("kg");
                let sizes = SizeMetrics::new(
                    keypair.public_key_len(),
                    keypair.secret_key_len(),
                    0,
                );
                (keypair, sizes)
            },
            |(keypair, _)| keypair.sign(message).expect("sign"),
            |(keypair, _), signature| {
                keypair.verify(message, signature).expect("verify");
            },
            |(_, sizes), signature| {
                SizeMetrics::new(
                    sizes.public_key_bytes,
                    sizes.secret_key_bytes,
                    signature.len(),
                )
            },
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
        Ok(measure_benchmark_flow(
            || Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize),
            |(_, secret_key)| {
                prepare_sk_for_epoch(secret_key, 1);
                Scheme::sign(secret_key, 1, &message).expect("sign")
            },
            |(public_key, _), signature| {
                Scheme::verify(public_key, 1, &message, signature);
            },
            |(public_key, secret_key), signature| {
                SizeMetrics::new(
                    public_key.to_bytes().len(),
                    secret_key.to_bytes().len(),
                    signature.to_bytes().len(),
                )
            },
        ))
    }
}

struct SubprocessAdapter {
    algorithm: &'static str,
    param_set: &'static str,
    executable: PathBuf,
    message_size: usize,
}

impl DsaBenchmark for SubprocessAdapter {
    fn name(&self) -> &str {
        self.algorithm
    }

    fn param_set(&self) -> &str {
        self.param_set
    }

    fn run_once(&self, _message: &[u8]) -> Result<BenchRun, String> {
        let output = Command::new(&self.executable)
            .args([
                "--format",
                "json",
                "--message-size",
                &self.message_size.to_string(),
            ])
            .output()
            .map_err(|err| {
                format!(
                    "failed to execute {}: {err}",
                    self.executable.display()
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "exit {}: {}",
                output.status,
                stderr.lines().last().unwrap_or("")
            ));
        }

        let report: BenchmarkBinaryReport =
            serde_json::from_slice(&output.stdout)
                .map_err(|err| format!("invalid benchmark JSON: {err}"))?;

        Ok(BenchRun::from_binary_report(&report))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliConfig {
    runs: usize,
    output: PathBuf,
    only_filters: Vec<String>,
    param_set_filters: Vec<String>,
    skip_ffi: bool,
    message_size: usize,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            runs: 10,
            output: PathBuf::from("benchmarks/results.csv"),
            only_filters: Vec::new(),
            param_set_filters: Vec::new(),
            skip_ffi: false,
            message_size: BENCH_MESSAGE.len(),
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
                "--only" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--only requires a value".to_string())?;
                    config.only_filters.push(value.to_ascii_lowercase());
                }
                "--param-set" => {
                    let value = args.next().ok_or_else(|| {
                        "--param-set requires a value".to_string()
                    })?;
                    config.param_set_filters.push(value.to_ascii_lowercase());
                }
                "--skip-ffi" => config.skip_ffi = true,
                "--message-size" => {
                    let value = args.next().ok_or_else(|| {
                        "--message-size requires a value".to_string()
                    })?;
                    config.message_size = value.parse().map_err(|_| {
                        format!("invalid message size: {value}")
                    })?;
                    if config.message_size == 0 {
                        return Err(
                            "--message-size must be greater than 0".to_string()
                        );
                    }
                }
                "--help" | "-h" => return Ok(Self::Help),
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        Ok(Self::Run(config))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendKind {
    Pure,
    Ffi,
}

#[derive(Clone, Copy)]
struct AdapterSpec {
    algorithm: &'static str,
    param_set: &'static str,
    backend: BackendKind,
    builder: fn(&RunnerContext, &'static AdapterSpec) -> Box<dyn DsaBenchmark>,
}

struct RunnerContext {
    message_size: usize,
    ffi_executables: HashMap<&'static str, PathBuf>,
}

fn build_dilithium(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(DilithiumAdapter)
}

fn build_falcon(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(FalconAdapter)
}

fn build_sphincs_plus(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(SphincsPlusAdapter)
}

fn build_mayo(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(MayoAdapter)
}

fn build_lms(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(LmsAdapter)
}

fn build_hss(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(HssAdapter)
}

fn build_xmss(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(XmssAdapter)
}

fn build_xmssmt(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(XmssmtAdapter)
}

fn build_leansig(
    _context: &RunnerContext,
    _spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(LeansigAdapter)
}

fn build_ffi_adapter(
    context: &RunnerContext,
    spec: &'static AdapterSpec,
) -> Box<dyn DsaBenchmark> {
    Box::new(SubprocessAdapter {
        algorithm: spec.algorithm,
        param_set: spec.param_set,
        executable: context
            .ffi_executables
            .get(spec.algorithm)
            .expect("ffi executable should be resolved")
            .clone(),
        message_size: context.message_size,
    })
}

static ADAPTER_SPECS: &[AdapterSpec] = &[
    AdapterSpec {
        algorithm: "ML-DSA-65 (Dilithium)",
        param_set: "ML-DSA-65",
        backend: BackendKind::Pure,
        builder: build_dilithium,
    },
    AdapterSpec {
        algorithm: "Falcon-512",
        param_set: "Falcon-512",
        backend: BackendKind::Pure,
        builder: build_falcon,
    },
    AdapterSpec {
        algorithm: "SPHINCS+-SHAKE-128f",
        param_set: "SPHINCS+-SHAKE-128f-simple",
        backend: BackendKind::Pure,
        builder: build_sphincs_plus,
    },
    AdapterSpec {
        algorithm: "MAYO-1",
        param_set: "MAYO-1",
        backend: BackendKind::Pure,
        builder: build_mayo,
    },
    AdapterSpec {
        algorithm: "LMS",
        param_set: "LMS-SHA256-M32-H5",
        backend: BackendKind::Pure,
        builder: build_lms,
    },
    AdapterSpec {
        algorithm: "HSS",
        param_set: "HSS-SHA256-H5-W2-L1",
        backend: BackendKind::Pure,
        builder: build_hss,
    },
    AdapterSpec {
        algorithm: "XMSS",
        param_set: "XMSS-SHA2_10_256",
        backend: BackendKind::Pure,
        builder: build_xmss,
    },
    AdapterSpec {
        algorithm: "XMSS^MT",
        param_set: "XMSSMT-SHA2_20/2_256",
        backend: BackendKind::Pure,
        builder: build_xmssmt,
    },
    AdapterSpec {
        algorithm: "LeanSig",
        param_set: "Poseidon-L2^18-TS-w4",
        backend: BackendKind::Pure,
        builder: build_leansig,
    },
    AdapterSpec {
        algorithm: "SQISign",
        param_set: "SQISign-lvl1",
        backend: BackendKind::Ffi,
        builder: build_ffi_adapter,
    },
    AdapterSpec {
        algorithm: "LESS",
        param_set: "LESS-252-45",
        backend: BackendKind::Ffi,
        builder: build_ffi_adapter,
    },
    AdapterSpec {
        algorithm: "CROSS",
        param_set: "CROSS-RSDPG-192-BAL",
        backend: BackendKind::Ffi,
        builder: build_ffi_adapter,
    },
];

fn selected_specs(config: &CliConfig) -> Vec<&'static AdapterSpec> {
    ADAPTER_SPECS
        .iter()
        .filter(|spec| {
            (!config.skip_ffi || spec.backend != BackendKind::Ffi)
                && matches_filter(spec.algorithm, &config.only_filters)
                && matches_filter(spec.param_set, &config.param_set_filters)
        })
        .collect()
}

fn matches_filter(value: &str, filters: &[String]) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| value.to_ascii_lowercase().contains(filter))
}

fn copy_into_fixed<const N: usize>(message: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let len = message.len().min(N);
    output[..len].copy_from_slice(&message[..len]);
    output
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

struct CsvReporter {
    writer: csv::Writer<std::fs::File>,
}

impl CsvReporter {
    fn new(path: &Path) -> std::io::Result<Self> {
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

    fn write_result(&mut self, result: &BenchResult) -> csv::Result<()> {
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bench_runner should live under crates/ in workspace")
        .to_path_buf()
}

fn resolve_ffi_binaries(
    specs: &[&'static AdapterSpec],
) -> Result<HashMap<&'static str, PathBuf>, String> {
    let ffi_specs: Vec<_> = specs
        .iter()
        .copied()
        .filter(|spec| spec.backend == BackendKind::Ffi)
        .collect();

    if ffi_specs.is_empty() {
        return Ok(HashMap::new());
    }

    let workspace_root = workspace_root();
    let mut build = Command::new("cargo");
    build
        .current_dir(&workspace_root)
        .args(["build", "--release"]);
    for spec in &ffi_specs {
        build.args(["--bin", ffi_bin_name(spec.algorithm)?]);
    }
    let status = build
        .status()
        .map_err(|err| format!("failed to build FFI binaries: {err}"))?;
    if !status.success() {
        return Err(format!("release build failed with status {status}"));
    }

    let mut binaries = HashMap::new();
    let target_dir = workspace_root.join("target").join("release");
    for spec in ffi_specs {
        let bin_name = ffi_bin_name(spec.algorithm)?;
        let executable = target_dir
            .join(format!("{bin_name}{}", std::env::consts::EXE_SUFFIX));
        if !executable.exists() {
            return Err(format!(
                "expected executable not found: {}",
                executable.display()
            ));
        }
        binaries.insert(spec.algorithm, executable);
    }

    Ok(binaries)
}

fn ffi_bin_name(algorithm: &str) -> Result<&'static str, String> {
    match algorithm {
        "SQISign" => Ok("sqisign"),
        "LESS" => Ok("less"),
        "CROSS" => Ok("cross"),
        _ => Err(format!("unknown ffi algorithm: {algorithm}")),
    }
}

fn instantiate_adapters(
    specs: &[&'static AdapterSpec],
    context: &RunnerContext,
) -> Vec<Box<dyn DsaBenchmark>> {
    specs
        .iter()
        .map(|spec| (spec.builder)(context, spec))
        .collect()
}

fn print_banner(total: usize, config: &CliConfig) {
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

fn print_help() {
    println!("Usage: bench_runner [options]");
    println!(
        "  --runs N              Number of benchmark samples per algorithm"
    );
    println!("  --output PATH         CSV output path");
    println!(
        "  --only TEXT           Filter algorithms by substring (repeatable)"
    );
    println!(
        "  --param-set TEXT      Filter param sets by substring (repeatable)"
    );
    println!("  --skip-ffi            Skip subprocess-based FFI algorithms");
    println!("  --message-size N      Benchmark message size in bytes");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_action_parses_filters_and_message_size() {
        let action = CliAction::parse([
            "--runs".to_string(),
            "7".to_string(),
            "--only".to_string(),
            "xmss".to_string(),
            "--param-set".to_string(),
            "sha2".to_string(),
            "--message-size".to_string(),
            "256".to_string(),
        ])
        .expect("config should parse");

        match action {
            CliAction::Run(config) => {
                assert_eq!(config.runs, 7);
                assert_eq!(config.only_filters, vec!["xmss"]);
                assert_eq!(config.param_set_filters, vec!["sha2"]);
                assert_eq!(config.message_size, 256);
            }
            CliAction::Help => panic!("expected run config"),
        }
    }

    #[test]
    fn cli_action_rejects_zero_message_size() {
        let err =
            CliAction::parse(["--message-size".to_string(), "0".to_string()])
                .expect_err("zero message size should fail");
        assert_eq!(err, "--message-size must be greater than 0");
    }

    #[test]
    fn selected_specs_respect_filters() {
        let mut config = CliConfig::default();
        config.only_filters.push("xmss".to_string());
        config.param_set_filters.push("20/2".to_string());
        let specs = selected_specs(&config);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].algorithm, "XMSS^MT");
    }

    #[test]
    fn binary_report_conversion_keeps_sizes() {
        let run = BenchRun::from_binary_report(&BenchmarkBinaryReport {
            algorithm: "X".to_string(),
            backend: None,
            param_set: None,
            keygen_ns: 10,
            sign_ns: 20,
            verify_ns: 30,
            verified: true,
            sizes: pq_bench::BenchmarkSizeReport {
                public_key_bytes: 40,
                secret_key_bytes: 50,
                signature_bytes: 60,
                signed_message_bytes: None,
            },
            sign_peak_bytes: None,
            verify_peak_bytes: None,
        });

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
