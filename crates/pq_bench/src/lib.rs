//! Shared benchmark configuration for the **awesome-pq-signatures** workspace.
//!
//! All DSA crates sign the same canonical 32-byte message so that benchmark
//! results are directly comparable. The message is the SHA-256 hash of a
//! human-readable string defined in the workspace-level `bench_config.toml`
//! file.

mod alloc;
mod binary;
mod config;
mod ffi_signed_message;
mod message;
mod reporting;
mod timing;

pub use ffi_signed_message::{
    ffi_deterministic_keypair, ffi_deterministic_sign, ffi_keypair,
    ffi_locked_verify, ffi_sign, ffi_verify, with_deterministic_rng,
    with_ffi_lock, DeterministicRngProfile, FfiSignedMessageDimensions,
};
pub use {
    alloc::{AllocationTracker, AllocationTrackingAllocator},
    binary::{
        parse_benchmark_binary_config_or_exit, run_human_benchmark_binary,
        BenchmarkBinaryExecution,
    },
    config::{BenchmarkBinaryConfig, BenchmarkOutputFormat},
    message::{
        bench_message, benchmark_message, benchmark_seed_array,
        benchmark_seed_u64, signed_message_size, BENCHMARK_SEED_U64,
        BENCH_MESSAGE, BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
    },
    reporting::{
        build_standard_binary_report, build_standard_human_benchmark_report,
        emit_benchmark_report, emit_standard_benchmark_report,
        print_human_benchmark_report, BenchmarkBinaryReport,
        BenchmarkSizeReport, HumanBenchmarkLine, HumanBenchmarkReport,
        HumanBenchmarkSection, StandardBenchmarkHumanReport,
        StandardBinaryBenchmarkSpec, StandardHumanBenchmarkSpec,
    },
    timing::{duration_ns, format_ns, measure_time, median, print_timing},
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
