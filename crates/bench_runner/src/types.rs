use std::time::Duration;

use pq_bench::{median, BenchmarkBinaryReport};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SizeMetrics {
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

impl SizeMetrics {
    pub const fn new(
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
pub struct BenchRun {
    pub keygen_ns: u128,
    pub sign_ns: u128,
    pub verify_ns: u128,
    pub sizes: SizeMetrics,
}

impl BenchRun {
    pub fn from_durations(
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

    pub fn from_binary_report(report: &BenchmarkBinaryReport) -> Self {
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
pub struct BenchResult {
    pub algorithm: String,
    pub param_set: String,
    pub keygen_median_ns: u128,
    pub sign_median_ns: u128,
    pub verify_median_ns: u128,
    pub sizes: SizeMetrics,
}

impl BenchResult {
    pub fn from_runs(adapter: &dyn DsaBenchmark, runs: &[BenchRun]) -> Self {
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

pub trait DsaBenchmark {
    fn name(&self) -> &str;
    fn param_set(&self) -> &str;
    fn run_once(&self, message: &[u8]) -> Result<BenchRun, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
