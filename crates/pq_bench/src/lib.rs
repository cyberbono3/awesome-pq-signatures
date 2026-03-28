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
#[macro_use]
mod macros;
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
        build_standard_benchmark_execution,
        parse_benchmark_binary_config_or_exit, run_human_benchmark_binary,
        run_standard_signed_message_benchmark_binary, BenchmarkBinaryExecution,
        StandardBenchmarkExecutionSpec, StandardBenchmarkSizes,
        StandardSignedMessageBinaryLabels,
    },
    config::{BenchmarkBinaryConfig, BenchmarkOutputFormat},
    message::{
        bench_message, benchmark_message, benchmark_seed_array,
        benchmark_seed_u64, expand_seed_u64, filled_message,
        signed_message_size, BENCHMARK_SEED_U64, BENCH_MESSAGE,
        BENCH_MESSAGE_BYTE, BENCH_MESSAGE_SIZES,
    },
    reporting::{
        build_standard_binary_report, build_standard_human_benchmark_report,
        emit_benchmark_report, emit_standard_benchmark_report,
        print_human_benchmark_report, BenchmarkBinaryReport,
        BenchmarkSizeReport, HumanBenchmarkLine, HumanBenchmarkReport,
        HumanBenchmarkSection, StandardBenchmarkHumanReport,
        StandardBinaryBenchmarkSpec, StandardHumanBenchmarkSpec,
    },
    timing::{
        duration_ns, format_ns, measure_time, median, parse_bool_env,
        parse_usize_env, print_timing, run_with_large_stack,
        BenchmarkOperation,
    },
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{c_int, c_uchar, c_ulonglong};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Mutex;

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
    fn filled_message_uses_requested_fill_byte() {
        let message = filled_message(8, 0x3C);
        assert_eq!(message, vec![0x3C; 8]);
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
    fn expand_seed_u64_is_deterministic() {
        assert_eq!(expand_seed_u64::<16>(7), expand_seed_u64::<16>(7));
        assert_ne!(expand_seed_u64::<16>(7), expand_seed_u64::<16>(8));
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

    mod simple_scheme_macro_fixture {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct KeyPair {
            public_key: Vec<u8>,
            secret_key: Vec<u8>,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct Signature(Vec<u8>);

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum Error {
            Failed,
        }

        declare_simple_signed_message_scheme!(
            scheme_type = Scheme,
            scheme_const = SCHEME,
            sizes_type = Sizes,
            keypair_type = KeyPair,
            signature_type = Signature,
            error_type = Error,
            variant = "fixture-simple",
            keygen = || {
                Ok::<KeyPair, Error>(KeyPair {
                    public_key: vec![1, 2, 3],
                    secret_key: vec![4, 5, 6, 7],
                })
            },
            sign = |keypair: &KeyPair, message: &[u8]| {
                if keypair.secret_key.is_empty() {
                    Err(Error::Failed)
                } else {
                    Ok::<Signature, Error>(Signature(message.to_vec()))
                }
            },
            verify =
                |_keypair: &KeyPair, message: &[u8], signature: &Signature| {
                    Ok::<bool, Error>(signature.0 == message)
                },
            public_key_size = |keypair: &KeyPair| keypair.public_key.len(),
            secret_key_size = |keypair: &KeyPair| keypair.secret_key.len(),
            signature_size = |signature: &Signature| signature.0.len()
        );
    }

    #[test]
    fn simple_signed_message_scheme_macro_generates_expected_api() {
        let scheme = simple_scheme_macro_fixture::SCHEME;
        let message = b"macro";

        let _ = scheme
            .benchmark_keypair()
            .expect("benchmark keypair generation should work");
        let keypair = scheme.keypair().expect("keypair generation should work");
        let signature = scheme
            .sign_message(&keypair, message)
            .expect("signing should work");

        assert_eq!(scheme.algorithm_name(), "fixture-simple");
        assert!(scheme
            .verify_message(&keypair, message, &signature)
            .expect("verification should work"));

        let sizes = scheme.sizes(&keypair, &signature);
        assert_eq!(sizes.public_key, 3);
        assert_eq!(sizes.secret_key, 4);
        assert_eq!(sizes.signature, message.len());
    }

    mod ffi_scheme_macro_fixture {
        use super::*;

        const SEED_BYTES: usize = 4;
        pub const KEYGEN_PROFILE: DeterministicRngProfile<SEED_BYTES> =
            DeterministicRngProfile {
                seed: [1, 2, 3, 4],
                domain_separator: 7,
            };
        pub const SIGN_PROFILE: DeterministicRngProfile<SEED_BYTES> =
            DeterministicRngProfile {
                seed: [4, 3, 2, 1],
                domain_separator: 9,
            };
        static FFI_LOCK: Mutex<()> = Mutex::new(());
        pub static LAST_DOMAIN_SEPARATOR: AtomicU16 = AtomicU16::new(0);

        declare_ffi_signed_message_backend!(
            native_type = NativeFixture,
            init_rng = init_rng,
            seed_bytes = SEED_BYTES,
            seed_length_error = "fixture seed length fits in u32",
            init_rng_fn = fixture_init_rng,
            public_key_bytes_fn = fixture_public_key_bytes,
            secret_key_bytes_fn = fixture_secret_key_bytes,
            signature_bytes_fn = fixture_signature_bytes
        );

        declare_ffi_signed_message_scheme!(
            seed_type = FixtureSeed,
            scheme_type = Scheme,
            scheme_const = SCHEME,
            keypair_type = FixtureKeyPair,
            signature_type = FixtureSignature,
            sizes_type = FixtureSizes,
            error_type = FixtureError,
            variant = "fixture-ffi",
            seed_bytes = SEED_BYTES,
            keygen_profile = KEYGEN_PROFILE,
            sign_profile = SIGN_PROFILE,
            ffi_lock = FFI_LOCK,
            dimensions = NativeFixture::dimensions(),
            init_rng = init_rng,
            keypair_fn = fixture_keypair,
            sign_fn = fixture_sign,
            verify_fn = fixture_verify
        );

        unsafe fn fixture_init_rng(
            _seed: *const c_uchar,
            _seed_len: u32,
            dsc: u16,
        ) {
            LAST_DOMAIN_SEPARATOR.store(dsc, Ordering::Relaxed);
        }

        unsafe fn fixture_public_key_bytes() -> usize {
            3
        }

        unsafe fn fixture_secret_key_bytes() -> usize {
            4
        }

        unsafe fn fixture_signature_bytes() -> usize {
            4
        }

        unsafe fn fixture_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int {
            unsafe {
                std::slice::from_raw_parts_mut(pk, fixture_public_key_bytes())
                    .copy_from_slice(&[10, 11, 12]);
                std::slice::from_raw_parts_mut(sk, fixture_secret_key_bytes())
                    .copy_from_slice(&[20, 21, 22, 23]);
            }
            0
        }

        unsafe fn fixture_sign(
            sm: *mut c_uchar,
            smlen: *mut c_ulonglong,
            m: *const c_uchar,
            mlen: c_ulonglong,
            _sk: *const c_uchar,
        ) -> c_int {
            let message_len =
                usize::try_from(mlen).expect("message length fits");
            let signature = [90_u8, 91, 92, 93];

            unsafe {
                let signed_message = std::slice::from_raw_parts_mut(
                    sm,
                    message_len + signature.len(),
                );
                signed_message[..message_len].copy_from_slice(
                    std::slice::from_raw_parts(m, message_len),
                );
                signed_message[message_len..].copy_from_slice(&signature);
                *smlen = c_ulonglong::try_from(signed_message.len())
                    .expect("length fits");
            }
            0
        }

        unsafe fn fixture_verify(
            m: *mut c_uchar,
            mlen: *mut c_ulonglong,
            sm: *const c_uchar,
            smlen: c_ulonglong,
            _pk: *const c_uchar,
        ) -> c_int {
            let signed_message_len =
                usize::try_from(smlen).expect("signed message length fits");
            let signature = [90_u8, 91, 92, 93];
            let message_len = signed_message_len - signature.len();

            unsafe {
                let signed_message =
                    std::slice::from_raw_parts(sm, signed_message_len);
                if signed_message[message_len..] != signature {
                    return -1;
                }
                std::slice::from_raw_parts_mut(m, message_len)
                    .copy_from_slice(&signed_message[..message_len]);
                *mlen =
                    c_ulonglong::try_from(message_len).expect("length fits");
            }
            0
        }
    }

    #[test]
    fn ffi_signed_message_scheme_macros_generate_expected_api() {
        let scheme = ffi_scheme_macro_fixture::SCHEME;
        assert_eq!(scheme.algorithm_name(), "fixture-ffi");
        let keypair = scheme
            .benchmark_keypair()
            .expect("ffi keypair generation should work");

        assert_eq!(
            ffi_scheme_macro_fixture::LAST_DOMAIN_SEPARATOR
                .load(Ordering::Relaxed),
            ffi_scheme_macro_fixture::KEYGEN_PROFILE.domain_separator
        );

        let signature = scheme
            .sign_message(&keypair, b"ffi")
            .expect("ffi signing should work");

        assert_eq!(keypair.public_key().len(), 3);
        assert_eq!(keypair.secret_key().len(), 4);

        assert_eq!(
            ffi_scheme_macro_fixture::LAST_DOMAIN_SEPARATOR
                .load(Ordering::Relaxed),
            ffi_scheme_macro_fixture::SIGN_PROFILE.domain_separator
        );

        assert!(scheme
            .verify_message(&keypair, b"ffi", &signature)
            .expect("ffi verification should work"));

        let sizes = scheme.sizes(&keypair, &signature);
        assert_eq!(sizes.public_key, 3);
        assert_eq!(sizes.secret_key, 4);
        assert_eq!(sizes.signature, 4);
    }
}
