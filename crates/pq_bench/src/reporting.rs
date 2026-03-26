use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::time::Duration;

use crate::{
    duration_ns, print_timing, BenchmarkBinaryConfig, BenchmarkOutputFormat,
};

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

pub struct StandardBinaryBenchmarkSpec<'a> {
    pub algorithm: &'a str,
    pub backend: Option<&'a str>,
    pub param_set: Option<&'a str>,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub verified: bool,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
    pub signed_message_bytes: Option<usize>,
    pub sign_peak_bytes: Option<usize>,
    pub verify_peak_bytes: Option<usize>,
}

pub fn build_standard_binary_report(
    spec: StandardBinaryBenchmarkSpec<'_>,
) -> BenchmarkBinaryReport {
    BenchmarkBinaryReport {
        algorithm: spec.algorithm.to_string(),
        backend: spec.backend.map(str::to_string),
        param_set: spec.param_set.map(str::to_string),
        keygen_ns: duration_ns(spec.keygen_duration),
        sign_ns: duration_ns(spec.sign_duration),
        verify_ns: duration_ns(spec.verify_duration),
        verified: spec.verified,
        sizes: BenchmarkSizeReport {
            public_key_bytes: spec.public_key_bytes,
            secret_key_bytes: spec.secret_key_bytes,
            signature_bytes: spec.signature_bytes,
            signed_message_bytes: spec.signed_message_bytes,
        },
        sign_peak_bytes: spec.sign_peak_bytes,
        verify_peak_bytes: spec.verify_peak_bytes,
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

pub struct StandardHumanBenchmarkSpec<'a> {
    pub banner_lines: &'a [&'a str],
    pub heading: Cow<'a, str>,
    pub intro_lines: Vec<HumanBenchmarkLine<'a>>,
    pub summary_algorithm: Cow<'a, str>,
    pub summary_intro_lines: Vec<HumanBenchmarkLine<'a>>,
    pub keygen_duration: Duration,
    pub sign_duration: Duration,
    pub verify_duration: Duration,
    pub verified: bool,
    pub size_lines: Vec<HumanBenchmarkLine<'a>>,
    pub summary_size_lines: Vec<HumanBenchmarkLine<'a>>,
    pub sign_peak_bytes: Option<usize>,
    pub verify_peak_bytes: Option<usize>,
}

pub fn build_standard_human_benchmark_report<'a>(
    spec: StandardHumanBenchmarkSpec<'a>,
) -> HumanBenchmarkReport<'a> {
    let sign_detail_lines = spec
        .sign_peak_bytes
        .map(|bytes| {
            vec![HumanBenchmarkLine::bytes(
                "Peak memory during signing",
                bytes,
            )]
        })
        .unwrap_or_default();
    let verify_detail_lines = spec
        .verify_peak_bytes
        .map(|bytes| {
            vec![HumanBenchmarkLine::bytes(
                "Peak memory during verification",
                bytes,
            )]
        })
        .unwrap_or_default();

    let mut memory_lines = Vec::new();
    if let Some(bytes) = spec.sign_peak_bytes {
        memory_lines.push(HumanBenchmarkLine::bytes("Signing", bytes));
    }
    if let Some(bytes) = spec.verify_peak_bytes {
        memory_lines.push(HumanBenchmarkLine::bytes("Verification", bytes));
    }

    let summary_sections = if memory_lines.is_empty() {
        Vec::new()
    } else {
        vec![HumanBenchmarkSection {
            title: "Memory Usage (heap allocations)",
            lines: memory_lines,
        }]
    };

    HumanBenchmarkReport {
        banner_lines: spec.banner_lines,
        heading: spec.heading,
        intro_lines: spec.intro_lines,
        summary_algorithm: spec.summary_algorithm,
        summary_intro_lines: spec.summary_intro_lines,
        keygen_duration: spec.keygen_duration,
        sign_duration: spec.sign_duration,
        verify_duration: spec.verify_duration,
        sign_detail_lines,
        verify_detail_lines,
        verified: spec.verified,
        size_lines: spec.size_lines,
        summary_size_lines: spec.summary_size_lines,
        summary_sections,
    }
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
