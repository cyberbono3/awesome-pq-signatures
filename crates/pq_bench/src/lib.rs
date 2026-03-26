//! Shared benchmark configuration for the **awesome-pq-signatures** workspace.
//!
//! All DSA crates sign the same canonical 32-byte message so that benchmark
//! results are directly comparable. The message is the SHA-256 hash of a
//! human-readable string defined in the workspace-level `bench_config.toml`
//! file.

mod alloc;
mod bench_support;
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
    bench_support::{
        print_signed_message_memory_usage, print_signed_message_sizes,
        signed_fixture,
    },
    binary::{
        parse_benchmark_binary_config_or_exit, run_human_benchmark_binary,
        run_standard_signed_message_benchmark_binary, BenchmarkBinaryExecution,
        StandardBenchmarkSizes, StandardSignedMessageBinaryLabels,
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

#[macro_export]
macro_rules! declare_ffi_signed_message_scheme {
    (
        seed_type = $seed_type:ident,
        scheme_type = $scheme_type:ident,
        scheme_const = $scheme_const:ident,
        keypair_type = $keypair_type:ident,
        signature_type = $signature_type:ident,
        sizes_type = $sizes_type:ident,
        error_type = $error_type:ident,
        variant = $variant:expr,
        seed_bytes = $seed_bytes:expr,
        keygen_profile = $keygen_profile:ident,
        sign_profile = $sign_profile:ident,
        ffi_lock = $ffi_lock:ident,
        dimensions = $dimensions:expr,
        init_rng = $init_rng:path,
        keypair_fn = $keypair_fn:path,
        sign_fn = $sign_fn:path,
        verify_fn = $verify_fn:path
    ) => {
        type $seed_type = [u8; $seed_bytes];

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $keypair_type {
            public_key: Vec<u8>,
            secret_key: Vec<u8>,
        }

        impl $keypair_type {
            #[must_use]
            pub fn public_key(&self) -> &[u8] {
                &self.public_key
            }

            #[must_use]
            pub fn secret_key(&self) -> &[u8] {
                &self.secret_key
            }
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $signature_type(Vec<u8>);

        impl $signature_type {
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $sizes_type {
            pub public_key: usize,
            pub secret_key: usize,
            pub signature: usize,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $error_type {
            FfiLockPoisoned,
            KeygenFailed(i32),
            SignFailed(i32),
            VerifyFailed(i32),
            InvalidSignedMessage,
            LengthOverflow,
        }

        #[derive(Clone, Copy, Debug, Default)]
        pub struct $scheme_type;

        pub const $scheme_const: $scheme_type = $scheme_type;

        impl $scheme_type {
            #[must_use]
            pub fn algorithm_name(&self) -> &'static str {
                $variant
            }

            /// # Errors
            ///
            /// Returns an error if the native key generation call fails or if
            /// the native runtime lock is poisoned.
            pub fn keypair(&self) -> Result<$keypair_type, $error_type> {
                self.keypair_with_seed($keygen_profile.seed)
            }

            /// # Errors
            ///
            /// Returns an error if the native key generation call fails or if
            /// the native runtime lock is poisoned.
            pub fn benchmark_keypair(
                &self,
            ) -> Result<$keypair_type, $error_type> {
                self.keypair()
            }

            /// # Errors
            ///
            /// Returns an error if the native key generation call fails or if
            /// the native runtime lock is poisoned.
            pub fn keypair_with_seed(
                &self,
                seed: $seed_type,
            ) -> Result<$keypair_type, $error_type> {
                let profile = $crate::DeterministicRngProfile {
                    seed,
                    domain_separator: $keygen_profile.domain_separator,
                };
                $crate::ffi_deterministic_keypair(
                    &$ffi_lock,
                    profile,
                    $init_rng,
                    $dimensions,
                    |public_key, secret_key| unsafe {
                        $keypair_fn(public_key, secret_key)
                    },
                    |public_key, secret_key| $keypair_type {
                        public_key,
                        secret_key,
                    },
                    || $error_type::FfiLockPoisoned,
                    $error_type::KeygenFailed,
                )
            }

            /// # Errors
            ///
            /// Returns an error if signing fails, the message length exceeds
            /// the native API width, or if the native runtime lock is poisoned.
            pub fn sign(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
            ) -> Result<$signature_type, $error_type> {
                $crate::ffi_deterministic_sign(
                    &$ffi_lock,
                    $sign_profile,
                    $init_rng,
                    $dimensions,
                    message,
                    &keypair.secret_key,
                    |signed_message,
                     signed_message_len,
                     message,
                     message_len,
                     secret_key| unsafe {
                        $sign_fn(
                            signed_message,
                            signed_message_len,
                            message,
                            message_len,
                            secret_key,
                        )
                    },
                    $signature_type,
                    || $error_type::FfiLockPoisoned,
                    $error_type::SignFailed,
                    || $error_type::LengthOverflow,
                    || $error_type::InvalidSignedMessage,
                )
            }

            /// # Errors
            ///
            /// Returns an error if signing fails, the message length exceeds
            /// the native API width, or if the native runtime lock is poisoned.
            pub fn sign_message(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
            ) -> Result<$signature_type, $error_type> {
                self.sign(keypair, message)
            }

            /// # Errors
            ///
            /// Returns an error if verification fails unexpectedly, the
            /// message length exceeds the native API width, or if the native
            /// runtime lock is poisoned.
            pub fn verify(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
                signature: &$signature_type,
            ) -> Result<bool, $error_type> {
                $crate::ffi_locked_verify(
                    &$ffi_lock,
                    message,
                    signature.as_bytes(),
                    &keypair.public_key,
                    |opened_message,
                     opened_message_len,
                     signed_message,
                     signed_message_len,
                     public_key| unsafe {
                        $verify_fn(
                            opened_message,
                            opened_message_len,
                            signed_message,
                            signed_message_len,
                            public_key,
                        )
                    },
                    || $error_type::FfiLockPoisoned,
                    $error_type::VerifyFailed,
                    || $error_type::LengthOverflow,
                )
            }

            /// # Errors
            ///
            /// Returns an error if verification fails unexpectedly, the
            /// message length exceeds the native API width, or if the native
            /// runtime lock is poisoned.
            pub fn verify_message(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
                signature: &$signature_type,
            ) -> Result<bool, $error_type> {
                self.verify(keypair, message, signature)
            }

            #[must_use]
            pub fn public_key_size(&self, _keypair: &$keypair_type) -> usize {
                $dimensions.public_key
            }

            #[must_use]
            pub fn secret_key_size(&self, _keypair: &$keypair_type) -> usize {
                $dimensions.secret_key
            }

            #[must_use]
            pub fn signature_size(
                &self,
                _signature: &$signature_type,
            ) -> usize {
                $dimensions.signature
            }

            #[must_use]
            pub fn sizes(
                &self,
                keypair: &$keypair_type,
                signature: &$signature_type,
            ) -> $sizes_type {
                $sizes_type {
                    public_key: self.public_key_size(keypair),
                    secret_key: self.secret_key_size(keypair),
                    signature: self.signature_size(signature),
                }
            }
        }
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
