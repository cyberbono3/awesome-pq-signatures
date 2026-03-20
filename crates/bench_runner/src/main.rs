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
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use pq_bench::BENCH_MESSAGE;

// ---------------------------------------------------------------------------
// Common types
// ---------------------------------------------------------------------------

struct BenchRun {
    keygen_ns: u128,
    sign_ns: u128,
    verify_ns: u128,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    signature_bytes: usize,
}

struct BenchResult {
    algorithm: String,
    param_set: String,
    keygen_median_ns: u128,
    sign_median_ns: u128,
    verify_median_ns: u128,
    public_key_bytes: usize,
    secret_key_bytes: usize,
    signature_bytes: usize,
}

trait DsaBenchmark {
    fn name(&self) -> &str;
    fn param_set(&self) -> &str;
    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    let n = values.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2
    }
}

fn format_ns(ns: u128) -> String {
    format!("{:.3}ms", ns as f64 / 1e6)
}

fn time_op<T, F: FnOnce() -> T>(f: F) -> (T, Duration) {
    let start = Instant::now();
    let val = f();
    (val, start.elapsed())
}

// ---------------------------------------------------------------------------
// In-process adapters (pure Rust)
// ---------------------------------------------------------------------------

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
        let (kp, kg) = time_op(|| ML_DSA_65.keypair(&seed));
        let (sig, s) = time_op(|| ML_DSA_65.sign(&kp, message, &[]).expect("sign"));
        let (_, v) = time_op(|| ML_DSA_65.verify(&kp, message, &[], &sig));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: ML_DSA_65.public_key_size(&kp),
            secret_key_bytes: ML_DSA_65.secret_key_size(&kp),
            signature_bytes: ML_DSA_65.signature_size(&sig),
        })
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
        let ((pk, sk), kg) = time_op(|| FALCON512.keypair());
        let (sm, s) = time_op(|| FALCON512.sign(message, &sk));
        let (_, v) = time_op(|| FALCON512.open(&sm, &pk));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: pk.as_bytes().len(),
            secret_key_bytes: sk.as_bytes().len(),
            signature_bytes: signature_size(&sm, message.len()),
        })
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
        use sphincs_plus::{signature_size, SignatureScheme as _, SPHINCS_PLUS_SHAKE_128F_SIMPLE};
        let ((pk, sk), kg) = time_op(|| SPHINCS_PLUS_SHAKE_128F_SIMPLE.keypair());
        let (sm, s) = time_op(|| SPHINCS_PLUS_SHAKE_128F_SIMPLE.sign(message, &sk));
        let (_, v) = time_op(|| SPHINCS_PLUS_SHAKE_128F_SIMPLE.open(&sm, &pk));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: pk.as_bytes().len(),
            secret_key_bytes: sk.as_bytes().len(),
            signature_bytes: signature_size(&sm, message.len()),
        })
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
        let (kp, kg) = time_op(|| MAYO.benchmark_keypair());
        let (sig, s) = time_op(|| MAYO.sign_message(&kp, message).expect("sign"));
        let (_, v) = time_op(|| MAYO.verify_message(&kp, message, &sig));
        let sz = MAYO.sizes(&kp, &sig);
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: sz.public_key_bytes,
            secret_key_bytes: sz.secret_key_bytes,
            signature_bytes: sz.signature_bytes,
        })
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
        let scheme =
            LmsScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME).map_err(|e| format!("{e:?}"))?;
        let ((pk, mut sk), kg) = time_op(|| scheme.keypair_with_seed(default_seed()).expect("kg"));
        let (sig, s) = time_op(|| scheme.sign(message, &mut sk).expect("sign"));
        let (_, v) = time_op(|| scheme.verify(message, &sig, &pk).expect("verify"));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: scheme.public_key_size(&pk),
            secret_key_bytes: scheme.secret_key_size(&sk),
            signature_bytes: scheme.signature_size(&sig),
        })
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
        let scheme =
            HssScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME).map_err(|e| format!("{e:?}"))?;
        let ((pk, mut sk), kg) = time_op(|| scheme.keypair_with_seed(default_seed()).expect("kg"));
        let (sig, s) = time_op(|| scheme.sign(message, &mut sk).expect("sign"));
        let (_, v) = time_op(|| scheme.verify(message, &sig, &pk).expect("verify"));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: scheme.public_key_size(&pk),
            secret_key_bytes: scheme.secret_key_size(&sk),
            signature_bytes: scheme.signature_size(&sig),
        })
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
        let ((pk, mut sk), kg) = time_op(|| scheme.keypair().expect("kg"));
        let (sig, s) = time_op(|| scheme.sign(message, &mut sk).expect("sign"));
        let (_, v) = time_op(|| scheme.verify(message, &sig, &pk).expect("verify"));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: pk.len(),
            secret_key_bytes: sk.len(),
            signature_bytes: sig.len(),
        })
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
        let (mut kp, kg) = time_op(|| scheme.keypair().expect("kg"));
        let pk_sz = kp.public_key_len();
        let sk_sz = kp.secret_key_len();
        let (sig, s) = time_op(|| kp.sign(message).expect("sign"));
        let (_, v) = time_op(|| kp.verify(message, &sig).expect("verify"));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: pk_sz,
            secret_key_bytes: sk_sz,
            signature_bytes: sig.len(),
        })
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
        type S = SIGTargetSumLifetime18W4NoOff;
        let mut msg = [0u8; MESSAGE_LENGTH];
        let n = message.len().min(MESSAGE_LENGTH);
        msg[..n].copy_from_slice(&message[..n]);
        let mut rng = rand::rng();
        let ((pk, mut sk), kg) = time_op(|| S::key_gen(&mut rng, 0, S::LIFETIME as usize));
        prepare_sk_for_epoch(&mut sk, 1);
        let (sig, s) = time_op(|| S::sign(&sk, 1, &msg).expect("sign"));
        let (_, v) = time_op(|| S::verify(&pk, 1, &msg, &sig));
        Ok(BenchRun {
            keygen_ns: kg.as_nanos(),
            sign_ns: s.as_nanos(),
            verify_ns: v.as_nanos(),
            public_key_bytes: pk.to_bytes().len(),
            secret_key_bytes: sk.to_bytes().len(),
            signature_bytes: sig.to_bytes().len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Subprocess adapters for FFI crates
// ---------------------------------------------------------------------------

/// Parse the output of a standalone DSA binary to extract timing and sizes.
/// Expected output format (from existing main.rs binaries):
///   Time to generate keys (ns): 36266791
///   Time to sign (ns): 49825292
///   Time to verify (ns): 2700542
///   Public key size: 83 bytes
///   Secret key size: 48 bytes
///   Signature size: 22464 bytes
fn parse_binary_output(stdout: &str) -> Result<BenchRun, String> {
    fn extract_ns(text: &str, label: &str) -> Option<u128> {
        for line in text.lines() {
            if line.contains(label) && line.contains("(ns)") {
                return line.split(':').last()?.trim().parse().ok();
            }
        }
        None
    }
    fn extract_bytes(text: &str, label: &str) -> Option<usize> {
        for line in text.lines() {
            if line.contains(label) && line.contains("bytes") {
                let part = line.split(':').last()?.trim();
                return part.split_whitespace().next()?.parse().ok();
            }
        }
        None
    }

    let kg = extract_ns(stdout, "generate keys").ok_or("missing keygen timing")?;
    let s = extract_ns(stdout, "sign").ok_or("missing sign timing")?;
    let v = extract_ns(stdout, "verify").ok_or("missing verify timing")?;
    let pk = extract_bytes(stdout, "Public key size").ok_or("missing pk size")?;
    let sk = extract_bytes(stdout, "Secret key size").ok_or("missing sk size")?;
    let sig = extract_bytes(stdout, "Signature size").ok_or("missing sig size")?;

    Ok(BenchRun {
        keygen_ns: kg,
        sign_ns: s,
        verify_ns: v,
        public_key_bytes: pk,
        secret_key_bytes: sk,
        signature_bytes: sig,
    })
}

/// Adapter that runs a standalone binary N times and collects results.
struct SubprocessAdapter {
    algo_name: &'static str,
    param: &'static str,
    bin_name: &'static str,
}

impl DsaBenchmark for SubprocessAdapter {
    fn name(&self) -> &str {
        self.algo_name
    }
    fn param_set(&self) -> &str {
        self.param
    }
    fn run_once(&self, _message: &[u8]) -> Result<BenchRun, String> {
        let output = Command::new("cargo")
            .args(["run", "--release", "--bin", self.bin_name])
            .output()
            .map_err(|e| format!("spawn failed: {e}"))?;
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

// ---------------------------------------------------------------------------
// Runner logic
// ---------------------------------------------------------------------------

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

    let mut kg_t = Vec::with_capacity(runs);
    let mut s_t = Vec::with_capacity(runs);
    let mut v_t = Vec::with_capacity(runs);
    let (mut pk, mut sk, mut sig) = (0, 0, 0);

    for i in 0..runs {
        let r = adapter.run_once(message)?;
        kg_t.push(r.keygen_ns);
        s_t.push(r.sign_ns);
        v_t.push(r.verify_ns);
        if i == 0 {
            pk = r.public_key_bytes;
            sk = r.secret_key_bytes;
            sig = r.signature_bytes;
        }
    }

    let km = median(&mut kg_t);
    let sm = median(&mut s_t);
    let vm = median(&mut v_t);

    println!();
    println!("  ✓ keygen: median {}", format_ns(km));
    println!("  ✓ sign:   median {}", format_ns(sm));
    println!("  ✓ verify: median {}", format_ns(vm));
    println!("  ✓ sizes:  pk={pk} sk={sk} sig={sig} bytes");

    Ok(BenchResult {
        algorithm: adapter.name().to_string(),
        param_set: adapter.param_set().to_string(),
        keygen_median_ns: km,
        sign_median_ns: sm,
        verify_median_ns: vm,
        public_key_bytes: pk,
        secret_key_bytes: sk,
        signature_bytes: sig,
    })
}

fn write_csv(results: &[BenchResult], path: &std::path::Path) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut f = fs::File::create(path)?;
    writeln!(f, "algorithm,param_set,keygen_median_ns,sign_median_ns,verify_median_ns,public_key_bytes,secret_key_bytes,signature_bytes")?;
    for r in results {
        writeln!(
            f,
            "{},{},{},{},{},{},{},{}",
            r.algorithm,
            r.param_set,
            r.keygen_median_ns,
            r.sign_median_ns,
            r.verify_median_ns,
            r.public_key_bytes,
            r.secret_key_bytes,
            r.signature_bytes
        )?;
    }
    Ok(())
}

fn print_table(results: &mut [BenchResult]) {
    // Sort by signature size (ascending)
    results.sort_by_key(|r| r.signature_bytes);

    let aw = results
        .iter()
        .map(|r| r.algorithm.len())
        .max()
        .unwrap_or(9)
        .max(9);
    let pw = results
        .iter()
        .map(|r| r.param_set.len())
        .max()
        .unwrap_or(9)
        .max(9);
    let sep = format!(
        "|-{:-<aw$}-|-{:-<pw$}-|-{:-<12}-|-{:-<12}-|-{:-<12}-|-{:-<8}-|-{:-<8}-|-{:-<8}-|",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        aw = aw,
        pw = pw
    );
    let hdr = format!(
        "| {:<aw$} | {:<pw$} | {:>12} | {:>12} | {:>12} | {:>8} | {:>8} | {:>8} |",
        "Algorithm",
        "Param Set",
        "Keygen",
        "Sign",
        "Verify",
        "PK (B)",
        "SK (B)",
        "Sig (B)",
        aw = aw,
        pw = pw
    );
    println!("\n{sep}\n{hdr}\n{sep}");
    for r in results {
        println!(
            "| {:<aw$} | {:<pw$} | {:>12} | {:>12} | {:>12} | {:>8} | {:>8} | {:>8} |",
            r.algorithm,
            r.param_set,
            format_ns(r.keygen_median_ns),
            format_ns(r.sign_median_ns),
            format_ns(r.verify_median_ns),
            r.public_key_bytes,
            r.secret_key_bytes,
            r.signature_bytes,
            aw = aw,
            pw = pw
        );
    }
    println!("{sep}");
}

// ---------------------------------------------------------------------------
// CLI & Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut runs: usize = 10;
    let mut output = PathBuf::from("benchmarks/results.csv");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--runs" => {
                i += 1;
                runs = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(10);
            }
            "--output" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    output = PathBuf::from(v);
                }
            }
            "--help" | "-h" => {
                println!("Usage: bench_runner [--runs N] [--output PATH]");
                return;
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let message: &[u8] = &BENCH_MESSAGE;

    let adapters: Vec<Box<dyn DsaBenchmark>> = vec![
        Box::new(DilithiumAdapter),
        Box::new(FalconAdapter),
        Box::new(SphincsPlusAdapter),
        Box::new(MayoAdapter),
        Box::new(LmsAdapter),
        Box::new(HssAdapter),
        Box::new(XmssAdapter),
        Box::new(XmssmtAdapter),
        Box::new(LeansigAdapter),
        // FFI crates run as subprocesses (separate binaries)
        Box::new(SubprocessAdapter {
            algo_name: "SQISign",
            param: "SQISign-lvl1",
            bin_name: "sqisign",
        }),
        Box::new(SubprocessAdapter {
            algo_name: "LESS",
            param: "LESS-252-45",
            bin_name: "less",
        }),
        Box::new(SubprocessAdapter {
            algo_name: "CROSS",
            param: "CROSS-RSDPG-192-BAL",
            bin_name: "cross",
        }),
    ];

    let total = adapters.len();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  PQ Signature Benchmark Runner                       ║");
    println!(
        "║  {total} algorithms × {runs} run{}                          ║",
        if runs == 1 { "" } else { "s" }
    );
    println!("╚══════════════════════════════════════════════════════╝\n");

    let mut results = Vec::with_capacity(total);
    for (i, adapter) in adapters.iter().enumerate() {
        match run_benchmark(adapter.as_ref(), message, runs, i, total) {
            Ok(r) => {
                results.push(r);
                let _ = write_csv(&results, &output);
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
        output.display(),
        results.len(),
        total
    );
}
