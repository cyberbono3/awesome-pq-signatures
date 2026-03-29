//! Workspace macros for recurring benchmark crate patterns.
//!
//! These macros are intentionally narrow. They exist for repeated structural
//! boilerplate such as allocator installation, standard signed-message scheme
//! wrappers, and Divan benchmark entrypoint wiring. When behavior differs in a
//! meaningful way, prefer normal functions over adding another macro layer.

// Allocation macros

/// Declares the allocation tracker and allocator alias used by benchmark
/// binaries and benches that measure peak heap usage.
#[macro_export]
macro_rules! declare_tracking_allocator {
    () => {
        pub static ALLOCATION_TRACKER: $crate::AllocationTracker =
            $crate::AllocationTracker::new();
        pub type TrackingAllocator<A> = $crate::AllocationTrackingAllocator<A>;
    };
}

/// Declares a small `memory` module exposing peak-memory helpers backed by the
/// crate-local `ALLOCATION_TRACKER`.
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

/// Installs the tracking allocator over `std::alloc::System` for normal
/// binaries and tests.
#[macro_export]
macro_rules! install_system_tracking_allocator {
    ($tracking_allocator:ident, $tracker:ident) => {
        static SYSTEM_ALLOC: std::alloc::System = std::alloc::System;

        #[global_allocator]
        static GLOBAL: $tracking_allocator<std::alloc::System> =
            $tracking_allocator::new(&SYSTEM_ALLOC, &$tracker);
    };
}

/// Installs the tracking allocator over Divan's allocation profiler for bench
/// targets.
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

// Benchmark declaration macros

/// Generates `sign_*` and `verify_*` Divan bench entrypoints for parameterized
/// message-size benchmark helpers that already exist in the crate.
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

/// Generates the standard signed-message Divan benchmark shape used by the FFI
/// and wrapper crates.
#[macro_export]
macro_rules! declare_signed_message_divan_bench {
    (
        scheme = $scheme:expr,
        keypair = $keypair:ty,
        signature = $signature:ty,
        message_sizes = $message_sizes:expr,
        reset_peak = $reset_peak:path,
        peak_bytes = $peak_bytes:path
    ) => {
        fn benchmark_keypair() -> $keypair {
            $scheme
                .benchmark_keypair()
                .expect("key generation should succeed")
        }

        fn signed_fixture(
            message_size: usize,
        ) -> ($keypair, Vec<u8>, $signature) {
            $crate::signed_fixture(
                message_size,
                benchmark_keypair,
                |keypair, message| {
                    $scheme
                        .sign_message(keypair, message)
                        .expect("benchmark setup should sign message")
                },
            )
        }

        #[divan::bench]
        fn keygen(bencher: divan::Bencher) {
            bencher.bench(|| {
                divan::black_box(benchmark_keypair());
            });
        }

        #[divan::bench(args = $message_sizes)]
        fn sign(bencher: divan::Bencher, message_size: usize) {
            let keypair = benchmark_keypair();
            let message = $crate::bench_message(message_size);

            bencher.bench(|| {
                divan::black_box(
                    $scheme
                        .sign_message(
                            divan::black_box(&keypair),
                            divan::black_box(&message),
                        )
                        .expect("sign benchmark input should always be valid"),
                );
            });
        }

        #[divan::bench(args = $message_sizes)]
        fn verify(bencher: divan::Bencher, message_size: usize) {
            let (keypair, message, signature) = signed_fixture(message_size);

            bencher.bench(|| {
                divan::black_box(
                    $scheme
                        .verify_message(
                            divan::black_box(&keypair),
                            divan::black_box(&message),
                            divan::black_box(&signature),
                        )
                        .expect("verification should succeed"),
                );
            });
        }

        fn print_sizes() {
            $crate::print_signed_message_sizes(
                $scheme.algorithm_name(),
                &$message_sizes,
                benchmark_keypair,
                |keypair| $scheme.public_key_size(keypair),
                |keypair| $scheme.secret_key_size(keypair),
                |keypair, message| {
                    $scheme
                        .sign_message(keypair, message)
                        .expect("size measurement should sign message")
                },
                |signature| $scheme.signature_size(signature),
            );
        }

        fn print_memory_usage() {
            $crate::print_signed_message_memory_usage(
                $scheme.algorithm_name(),
                &$message_sizes,
                benchmark_keypair,
                |keypair, message| {
                    $scheme
                        .sign_message(keypair, message)
                        .expect("memory measurement should sign message")
                },
                |keypair, message, signature| {
                    let _verified = $scheme
                        .verify_message(keypair, message, signature)
                        .expect("verification should succeed");
                },
                $reset_peak,
                $peak_bytes,
            );
        }

        fn main() {
            print_sizes();
            print_memory_usage();
            divan::main();
        }
    };
}

// Scheme/binary wiring macros

/// Declares a benchmark parameter-set enum with the common string/OID lookup
/// surface used by crates that expose multiple named variants.
#[macro_export]
macro_rules! declare_benchmark_param_set {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident,
        error = $error_type:ty,
        unsupported = $unsupported:path,
        {
            $(
                $variant:ident => {
                    name: $display_name:expr,
                    oid: $oid:expr
                }
            ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        $vis enum $name {
            $($variant),+
        }

        impl $name {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $display_name),+
                }
            }

            #[must_use]
            pub const fn oid(self) -> u32 {
                match self {
                    $(Self::$variant => $oid),+
                }
            }

            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[$(Self::$variant),+]
            }
        }

        impl std::str::FromStr for $name {
            type Err = $error_type;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($display_name => Ok(Self::$variant)),+,
                    _ => Err($unsupported(value.to_owned())),
                }
            }
        }
    };
}

/// Declares a local parameter-dispatch macro that maps a runtime parameter-set
/// enum to concrete generic types.
#[macro_export]
macro_rules! declare_param_dispatch {
    (
        $dispatch_macro:ident,
        enum = $enum_name:ident,
        {
            $( $variant:ident => $param_ty:ty ),+ $(,)?
        }
    ) => {
        macro_rules! $dispatch_macro {
            ($param_set:expr, $param:ident => $body:expr) => {
                match $param_set {
                    $(
                        $enum_name::$variant => {
                            type $param = $param_ty;
                            $body
                        }
                    ),+
                }
            };
        }
    };
}

/// Generates a small scheme wrapper for implementations that already expose
/// normal Rust keygen/sign/verify operations and size accessors.
#[macro_export]
macro_rules! declare_simple_signed_message_scheme {
    (
        scheme_type = $scheme_type:ident,
        scheme_const = $scheme_const:ident,
        sizes_type = $sizes_type:ident,
        keypair_type = $keypair_type:ty,
        signature_type = $signature_type:ty,
        error_type = $error_type:ty,
        variant = $variant:expr,
        keygen = $keygen:expr,
        sign = $sign:expr,
        verify = $verify:expr,
        public_key_size = $public_key_size:expr,
        secret_key_size = $secret_key_size:expr,
        signature_size = $signature_size:expr
    ) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $sizes_type {
            pub public_key: usize,
            pub secret_key: usize,
            pub signature: usize,
        }

        #[derive(Clone, Copy, Debug, Default)]
        pub struct $scheme_type;

        pub const $scheme_const: $scheme_type = $scheme_type;

        impl $scheme_type {
            #[must_use]
            pub fn algorithm_name(&self) -> &'static str {
                $variant
            }

            pub fn keypair(&self) -> Result<$keypair_type, $error_type> {
                ($keygen)()
            }

            pub fn benchmark_keypair(
                &self,
            ) -> Result<$keypair_type, $error_type> {
                self.keypair()
            }

            pub fn sign(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
            ) -> Result<$signature_type, $error_type> {
                ($sign)(keypair, message)
            }

            pub fn sign_message(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
            ) -> Result<$signature_type, $error_type> {
                self.sign(keypair, message)
            }

            pub fn verify(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
                signature: &$signature_type,
            ) -> Result<bool, $error_type> {
                ($verify)(keypair, message, signature)
            }

            pub fn verify_message(
                &self,
                keypair: &$keypair_type,
                message: &[u8],
                signature: &$signature_type,
            ) -> Result<bool, $error_type> {
                self.verify(keypair, message, signature)
            }

            #[must_use]
            pub fn public_key_size(&self, keypair: &$keypair_type) -> usize {
                ($public_key_size)(keypair)
            }

            #[must_use]
            pub fn secret_key_size(&self, keypair: &$keypair_type) -> usize {
                ($secret_key_size)(keypair)
            }

            #[must_use]
            pub fn signature_size(&self, signature: &$signature_type) -> usize {
                ($signature_size)(signature)
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

/// Generates the repeated native-backend shim that exposes byte dimensions and
/// deterministic RNG initialization for FFI-backed signed-message schemes.
#[macro_export]
macro_rules! declare_ffi_signed_message_backend {
    (
        native_type = $native_type:ident,
        init_rng = $init_rng:ident,
        seed_bytes = $seed_bytes:expr,
        seed_length_error = $seed_length_error:expr,
        init_rng_fn = $init_rng_fn:path,
        public_key_bytes_fn = $public_key_bytes_fn:path,
        secret_key_bytes_fn = $secret_key_bytes_fn:path,
        signature_bytes_fn = $signature_bytes_fn:path
    ) => {
        struct $native_type;

        impl $native_type {
            fn dimensions() -> $crate::FfiSignedMessageDimensions {
                $crate::FfiSignedMessageDimensions {
                    public_key: unsafe { $public_key_bytes_fn() },
                    secret_key: unsafe { $secret_key_bytes_fn() },
                    signature: unsafe { $signature_bytes_fn() },
                }
            }
        }

        fn $init_rng(profile: &$crate::DeterministicRngProfile<$seed_bytes>) {
            let seed_len =
                u32::try_from($seed_bytes).expect($seed_length_error);
            unsafe {
                $init_rng_fn(
                    profile.seed.as_ptr(),
                    seed_len,
                    profile.domain_separator,
                );
            }
        }
    };
}

/// Generates the standard FFI-backed signed-message scheme wrapper used by
/// crates like `cross` and `less`.
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

/// Generates the standard standalone benchmark-binary `main` body for
/// signed-message schemes that already expose the common scheme API.
#[macro_export]
macro_rules! run_standard_signed_message_scheme_main {
    (
        scheme = $scheme:expr,
        algorithm = $algorithm:expr,
        param_set = $param_set:expr,
        heading_algorithm = $heading_algorithm:expr,
        heading_param_set = $heading_param_set:expr,
        summary_algorithm = $summary_algorithm:expr,
        backend = $backend:expr,
        reset_peak = $reset_peak:path,
        peak_bytes = $peak_bytes:path
    ) => {{
        let scheme = $scheme;
        $crate::run_standard_signed_message_benchmark_binary(
            std::env::args().skip(1),
            $crate::StandardSignedMessageBinaryLabels {
                algorithm: $algorithm,
                param_set: $param_set,
                heading_algorithm: $heading_algorithm,
                heading_param_set: $heading_param_set,
                summary_algorithm: $summary_algorithm,
                backend: $backend,
            },
            || {
                scheme
                    .benchmark_keypair()
                    .expect("key generation should succeed")
            },
            |keypair, message| {
                scheme
                    .sign_message(keypair, message)
                    .expect("signing should succeed")
            },
            |keypair, message, signature| {
                scheme
                    .verify_message(keypair, message, signature)
                    .expect("verification should succeed")
            },
            |keypair, signature| {
                let sizes = scheme.sizes(keypair, signature);
                $crate::StandardBenchmarkSizes {
                    public_key_bytes: sizes.public_key,
                    secret_key_bytes: sizes.secret_key,
                    signature_bytes: sizes.signature,
                }
            },
            $reset_peak,
            $peak_bytes,
        );
    }};
}
