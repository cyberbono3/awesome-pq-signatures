//! Shared benchmark configuration for the **awesome-pq-signatures** workspace.
//!
//! All DSA crates sign the same canonical 32-byte message so that benchmark
//! results are directly comparable. The message is the SHA-256 hash of a
//! human-readable string defined in the workspace-level `bench_config.toml`
//! file.

use serde::{Deserialize, Serialize};
use std::alloc::{GlobalAlloc, Layout};
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

mod ffi_signed_message;

include!(concat!(env!("OUT_DIR"), "/bench_message.rs"));

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const BENCHMARK_SEED_U64: u64 = 0x7A5B_91C3_E4D2_F607;

pub use ffi_signed_message::{
    ffi_keypair, ffi_sign, ffi_verify, with_deterministic_rng, with_ffi_lock,
    FfiSignedMessageDimensions,
};

#[macro_export]
macro_rules! declare_tracking_allocator {
    () => {
        pub static ALLOCATION_TRACKER: $crate::AllocationTracker =
            $crate::AllocationTracker::new();
        pub type TrackingAllocator<A> = $crate::AllocationTrackingAllocator<A>;
    };
}

#[macro_export]
macro_rules! declare_peak_memory_api {
    () => {
        pub mod memory {
            pub fn reset_peak() {
                super::ALLOCATION_TRACKER.reset_peak();
            }

            pub fn peak_bytes() -> usize {
                super::ALLOCATION_TRACKER.peak_bytes()
            }
        }
    };
}

#[macro_export]
macro_rules! install_system_tracking_allocator {
    ($tracking_allocator:ident, $tracker:ident) => {
        static SYSTEM_ALLOC: std::alloc::System = std::alloc::System;

        #[global_allocator]
        static GLOBAL: $tracking_allocator<std::alloc::System> =
            $tracking_allocator::new(&SYSTEM_ALLOC, &$tracker);
    };
}

#[macro_export]
macro_rules! install_divan_tracking_allocator {
    ($tracking_allocator:ident, $tracker:ident) => {
        static DIVAN_ALLOC: divan::AllocProfiler =
            divan::AllocProfiler::system();

        #[global_allocator]
        static ALLOC: $tracking_allocator<divan::AllocProfiler> =
            $tracking_allocator::new(&DIVAN_ALLOC, &$tracker);
    };
}

#[macro_export]
macro_rules! declare_param_message_benches {
    (
        sign = { $( $sign_fn:ident => $sign_param:expr ),+ $(,)? },
        verify = { $( $verify_fn:ident => $verify_param:expr ),+ $(,)? }
    ) => {
        $(
            #[divan::bench(args = BENCH_MESSAGE_SIZES)]
            fn $sign_fn(bencher: divan::Bencher, message_size: usize) {
                sign_bench(bencher, $sign_param, message_size);
            }
        )+

        $(
            #[divan::bench(args = BENCH_MESSAGE_SIZES)]
            fn $verify_fn(bencher: divan::Bencher, message_size: usize) {
                verify_bench(bencher, $verify_param, message_size);
            }
        )+
    };
}

pub fn bench_message(size: usize) -> Vec<u8> {
    vec![BENCH_MESSAGE_BYTE; size]
}

pub fn benchmark_message(size: usize) -> Vec<u8> {
    if size == BENCH_MESSAGE.len() {
        BENCH_MESSAGE.to_vec()
    } else {
        bench_message(size)
    }
}

pub fn benchmark_seed_u64() -> u64 {
    BENCHMARK_SEED_U64
}

pub fn benchmark_seed_array<const N: usize>() -> [u8; N] {
    let mut state = BENCHMARK_SEED_U64;
    let mut output = [0u8; N];
    let mut offset = 0;

    while offset < N {
        state = splitmix64(state);
        let chunk = state.to_le_bytes();
        let take = (N - offset).min(chunk.len());
        output[offset..offset + take].copy_from_slice(&chunk[..take]);
        offset += take;
    }

    output
}

pub fn signed_message_size(message_len: usize, signature_len: usize) -> usize {
    message_len.saturating_add(signature_len)
}

pub fn measure_time<T, F>(operation: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

pub fn median(values: &mut [u128]) -> u128 {
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

pub fn format_ns(ns: u128) -> String {
    format!("{:.3}ms", ns as f64 / 1e6)
}

pub fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

pub fn print_timing(label: &str, duration: Duration) {
    println!("Time to {label}: {duration:?}");
    println!("Time to {label} (ns): {}", duration.as_nanos());
}

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct BenchmarkSizeReport {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message_bytes: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkBinaryReport {
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_set: Option<String>,
    pub keygen_ns: u64,
    pub sign_ns: u64,
    pub verify_ns: u64,
    pub verified: bool,
    pub sizes: BenchmarkSizeReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_peak_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_peak_bytes: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkOutputFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkBinaryConfig {
    pub output_format: BenchmarkOutputFormat,
    pub message_size: usize,
}

impl Default for BenchmarkBinaryConfig {
    fn default() -> Self {
        Self {
            output_format: BenchmarkOutputFormat::Human,
            message_size: BENCH_MESSAGE.len(),
        }
    }
}

impl BenchmarkBinaryConfig {
    pub fn parse(
        args: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--format" => {
                    let value = args.next().ok_or_else(|| {
                        "--format requires a value".to_string()
                    })?;
                    config.output_format = match value.as_str() {
                        "human" => BenchmarkOutputFormat::Human,
                        "json" => BenchmarkOutputFormat::Json,
                        _ => {
                            return Err(format!(
                                "unsupported format: {value} (expected human or json)"
                            ))
                        }
                    };
                }
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
                "--help" | "-h" => {
                    return Err(
                        "usage: [--format human|json] [--message-size N]"
                            .to_string(),
                    )
                }
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        Ok(config)
    }
}

pub fn emit_benchmark_report(
    config: &BenchmarkBinaryConfig,
    report: &BenchmarkBinaryReport,
    render_human: impl FnOnce(&BenchmarkBinaryReport),
) {
    match config.output_format {
        BenchmarkOutputFormat::Human => render_human(report),
        BenchmarkOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(report)
                    .expect("benchmark report should serialize to JSON")
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanBenchmarkLine<'a> {
    pub label: &'a str,
    pub value: Cow<'a, str>,
}

impl<'a> HumanBenchmarkLine<'a> {
    pub fn new(label: &'a str, value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            label,
            value: value.into(),
        }
    }

    pub fn bytes(label: &'a str, bytes: usize) -> Self {
        Self::new(label, format!("{bytes} bytes"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HumanBenchmarkReport<'a> {
    pub banner_lines: &'a [&'a str],
    pub heading: Cow<'a, str>,
    pub intro_lines: Vec<HumanBenchmarkLine<'a>>,
    pub summary_algorithm: Cow<'a, str>,
    pub summary_intro_lines: Vec<HumanBenchmarkLine<'a>>,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub sign_detail_lines: Vec<HumanBenchmarkLine<'a>>,
    pub verify_detail_lines: Vec<HumanBenchmarkLine<'a>>,
    pub verified: bool,
    pub size_lines: Vec<HumanBenchmarkLine<'a>>,
    pub summary_size_lines: Vec<HumanBenchmarkLine<'a>>,
    pub summary_sections: Vec<HumanBenchmarkSection<'a>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HumanBenchmarkSection<'a> {
    pub title: &'a str,
    pub lines: Vec<HumanBenchmarkLine<'a>>,
}

pub fn print_human_benchmark_report(report: &HumanBenchmarkReport<'_>) {
    for line in report.banner_lines {
        println!("{line}");
    }
    if !report.banner_lines.is_empty() {
        println!();
    }

    println!("=== {} Benchmark ===\n", report.heading);
    print_human_report_lines(&report.intro_lines);
    if !report.intro_lines.is_empty() {
        println!();
    }

    println!("--- Key Generation ---");
    print_timing("generate keys", report.keygen_duration);
    println!("\n--- Signing ---");
    print_timing("sign", report.sign_duration);
    print_human_report_lines(&report.sign_detail_lines);
    println!("\n--- Verification ---");
    print_timing("verify", report.verify_duration);
    print_human_report_lines(&report.verify_detail_lines);
    println!(
        "Signature verification: {}",
        if report.verified { "SUCCESS" } else { "FAILED" }
    );

    println!("\n--- Size Measurements ---");
    print_human_report_lines(&report.size_lines);

    println!("\n=== Summary ===");
    println!("Algorithm: {}", report.summary_algorithm);
    print_human_report_lines(&report.summary_intro_lines);
    if !report.summary_intro_lines.is_empty() {
        println!();
    }
    println!("Timing:");
    println!(
        "  Key Generation: {:?} ({} ns)",
        report.keygen_duration,
        report.keygen_duration.as_nanos()
    );
    println!(
        "  Signing:        {:?} ({} ns)",
        report.sign_duration,
        report.sign_duration.as_nanos()
    );
    println!(
        "  Verification:   {:?} ({} ns)",
        report.verify_duration,
        report.verify_duration.as_nanos()
    );
    println!("\nSizes:");
    print_human_summary_lines(&report.summary_size_lines);
    for section in &report.summary_sections {
        println!("\n{}:", section.title);
        print_human_summary_lines(&section.lines);
    }
}

pub struct StandardBenchmarkHumanReport<'a> {
    pub heading_algorithm: &'a str,
    pub heading_param_set: &'a str,
    pub summary_algorithm: &'a str,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
    pub sign_peak_bytes: usize,
    pub verify_peak_bytes: usize,
}

pub fn emit_standard_benchmark_report(
    config: &BenchmarkBinaryConfig,
    report: &BenchmarkBinaryReport,
    human: StandardBenchmarkHumanReport<'_>,
) {
    emit_benchmark_report(config, report, |report| {
        println!(
            "=== {} ({}) Benchmark ===\n",
            human.heading_algorithm, human.heading_param_set
        );
        println!("--- Key Generation ---");
        print_timing("generate keys", human.keygen_duration);
        println!("\n--- Signing ---");
        print_timing("sign", human.sign_duration);
        println!(
            "Peak memory during signing: {} bytes",
            human.sign_peak_bytes
        );
        println!("\n--- Verification ---");
        print_timing("verify", human.verify_duration);
        println!(
            "Peak memory during verification: {} bytes",
            human.verify_peak_bytes
        );

        if report.verified {
            println!("Signature verification: SUCCESS");
        } else {
            println!("Signature verification: FAILED");
        }

        println!("\n--- Size Measurements ---");
        println!("Public key size: {} bytes", human.public_key_bytes);
        println!("Secret key size: {} bytes", human.secret_key_bytes);
        println!("Signature size: {} bytes", human.signature_bytes);
        println!(
            "Signed message size: {} bytes",
            report
                .sizes
                .signed_message_bytes
                .expect("signed message size should exist")
        );

        println!("\n=== Summary ===");
        println!("Algorithm: {}", human.summary_algorithm);
        println!("\nTiming:");
        println!(
            "  Key Generation: {:?} ({} ns)",
            human.keygen_duration, report.keygen_ns
        );
        println!(
            "  Signing:        {:?} ({} ns)",
            human.sign_duration, report.sign_ns
        );
        println!(
            "  Verification:   {:?} ({} ns)",
            human.verify_duration, report.verify_ns
        );
        println!("\nSizes:");
        println!("  Public Key:  {} bytes", human.public_key_bytes);
        println!("  Secret Key:  {} bytes", human.secret_key_bytes);
        println!("  Signature:   {} bytes", human.signature_bytes);
        println!("\nMemory Usage (heap allocations):");
        println!("  Signing:      {} bytes", human.sign_peak_bytes);
        println!("  Verification: {} bytes", human.verify_peak_bytes);
    });
}

fn print_human_report_lines(lines: &[HumanBenchmarkLine<'_>]) {
    for line in lines {
        println!("{}: {}", line.label, line.value);
    }
}

fn print_human_summary_lines(lines: &[HumanBenchmarkLine<'_>]) {
    for line in lines {
        println!("  {}: {}", line.label, line.value);
    }
}

pub struct AllocationTracker {
    allocated: AtomicUsize,
    peak_allocated: AtomicUsize,
    baseline: AtomicUsize,
    total_allocated: AtomicUsize,
    tracking_enabled: AtomicBool,
}

impl AllocationTracker {
    pub const fn new() -> Self {
        Self {
            allocated: AtomicUsize::new(0),
            peak_allocated: AtomicUsize::new(0),
            baseline: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
            tracking_enabled: AtomicBool::new(false),
        }
    }

    pub fn reset_peak(&self) {
        let current = self.allocated.load(Ordering::SeqCst);
        self.baseline.store(current, Ordering::SeqCst);
        self.peak_allocated.store(0, Ordering::SeqCst);
        self.total_allocated.store(0, Ordering::SeqCst);
        self.tracking_enabled.store(true, Ordering::SeqCst);
    }

    pub fn stop_tracking(&self) {
        self.tracking_enabled.store(false, Ordering::SeqCst);
    }

    pub fn peak_bytes(&self) -> usize {
        self.peak_allocated.load(Ordering::SeqCst)
    }

    pub fn total_allocated_bytes(&self) -> usize {
        self.total_allocated.load(Ordering::SeqCst)
    }

    pub fn current_bytes(&self) -> usize {
        self.allocated.load(Ordering::SeqCst)
    }

    fn track_alloc(&self, size: usize) {
        let current = self.allocated.fetch_add(size, Ordering::SeqCst) + size;

        if self.tracking_enabled.load(Ordering::SeqCst) {
            self.total_allocated.fetch_add(size, Ordering::SeqCst);
        }

        let baseline = self.baseline.load(Ordering::SeqCst);
        let relative_current = current.saturating_sub(baseline);
        let mut peak = self.peak_allocated.load(Ordering::SeqCst);

        while relative_current > peak {
            match self.peak_allocated.compare_exchange_weak(
                peak,
                relative_current,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }

    fn track_dealloc(&self, size: usize) {
        self.allocated.fetch_sub(size, Ordering::SeqCst);
    }
}

pub struct AllocationTrackingAllocator<A: GlobalAlloc + Sync + 'static> {
    inner: &'static A,
    tracker: &'static AllocationTracker,
}

impl<A: GlobalAlloc + Sync + 'static> AllocationTrackingAllocator<A> {
    pub const fn new(
        inner: &'static A,
        tracker: &'static AllocationTracker,
    ) -> Self {
        Self { inner, tracker }
    }
}

unsafe impl<A: GlobalAlloc + Sync + 'static> GlobalAlloc
    for AllocationTrackingAllocator<A>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            self.tracker.track_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        self.tracker.track_dealloc(layout.size());
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_message_is_32_bytes() {
        assert_eq!(BENCH_MESSAGE.len(), 32);
    }

    #[test]
    fn bench_message_is_not_all_zeros() {
        assert_ne!(BENCH_MESSAGE, [0u8; 32]);
    }

    #[test]
    fn bench_message_uses_expected_fill_byte() {
        let message = bench_message(16);
        assert_eq!(message.len(), 16);
        assert!(message.iter().all(|&byte| byte == BENCH_MESSAGE_BYTE));
    }

    #[test]
    fn benchmark_message_uses_canonical_message_at_default_size() {
        assert_eq!(
            benchmark_message(BENCH_MESSAGE.len()),
            BENCH_MESSAGE.to_vec()
        );
    }

    #[test]
    fn benchmark_seed_array_is_deterministic() {
        assert_eq!(benchmark_seed_array::<8>(), benchmark_seed_array::<8>());
        assert_ne!(benchmark_seed_array::<8>(), [0u8; 8]);
    }

    #[test]
    fn signed_message_size_adds_lengths() {
        assert_eq!(signed_message_size(10, 20), 30);
    }

    #[test]
    fn median_returns_expected_values() {
        let mut odd = [9_u128, 3, 5];
        assert_eq!(median(&mut odd), 5);

        let mut even = [9_u128, 3, 5, 1];
        assert_eq!(median(&mut even), 4);

        let mut empty: [u128; 0] = [];
        assert_eq!(median(&mut empty), 0);
    }

    #[test]
    fn format_ns_formats_milliseconds() {
        assert_eq!(format_ns(1_500_000), "1.500ms");
    }

    #[test]
    fn binary_config_parses_json_and_message_size() {
        let config = BenchmarkBinaryConfig::parse([
            "--format".to_string(),
            "json".to_string(),
            "--message-size".to_string(),
            "128".to_string(),
        ])
        .expect("config should parse");

        assert_eq!(config.output_format, BenchmarkOutputFormat::Json);
        assert_eq!(config.message_size, 128);
    }
}
