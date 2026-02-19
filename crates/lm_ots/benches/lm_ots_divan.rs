use divan::{black_box, AllocProfiler, Bencher};
use lm_ots::{
    bench_message, default_identifier, memory, seed_bytes_from_u64,
    seed_from_str, LmOtsParamSet, LmOtsScheme, TrackingAllocator,
    BENCH_MESSAGE_SIZES, LMOTS_Q,
};
use std::sync::atomic::{AtomicU64, Ordering};

const EXPECTED_ALGORITHM: &str = "LM-OTS";
const EXPECTED_BACKEND: &str = "lms-signature-0.1.0-rc.2";
const EXPECTED_PARAM_SET: &str = "LMOTS_SHA256_N32_W4";

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = checked_scheme();
    let id = default_identifier();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seed_base = seed_from_str("lm-ots-divan-keygen");

    bencher.bench(|| {
        let i = COUNTER.fetch_add(1, Ordering::Relaxed);
        black_box(scheme.keypair_with_seed(
            LMOTS_Q,
            id,
            seed_bytes_from_u64(seed_base ^ i),
        ));
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = checked_scheme();
    let id = default_identifier();
    let message = bench_message(message_size);
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let key_seed_base = seed_from_str("lm-ots-divan-sign-keygen");
    let sign_seed_base = seed_from_str("lm-ots-divan-sign");

    bencher.bench(|| {
        let i = COUNTER.fetch_add(1, Ordering::Relaxed);
        let (_public_key, mut secret_key) = scheme.keypair_with_seed(
            LMOTS_Q,
            id,
            seed_bytes_from_u64(key_seed_base ^ i),
        );
        let signature = scheme
            .sign_with_seed(&message, &mut secret_key, sign_seed_base ^ i)
            .expect("lm-ots sign should succeed");
        black_box(signature);
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = checked_scheme();
    let id = default_identifier();
    let message = bench_message(message_size);
    let (public_key, mut secret_key) = scheme.keypair_with_seed(
        LMOTS_Q,
        id,
        seed_bytes_from_u64(seed_from_str("lm-ots-divan-verify-keygen")),
    );
    let signature = scheme
        .sign_with_seed(
            &message,
            &mut secret_key,
            seed_from_str("lm-ots-divan-verify-sign"),
        )
        .expect("lm-ots sign should succeed");

    bencher.bench(|| {
        let valid = scheme
            .verify(&message, &signature, &public_key)
            .expect("lm-ots verify call should succeed");
        assert!(valid, "lm-ots verify must return true");
        black_box(valid);
    });
}

fn print_sizes() {
    let scheme = checked_scheme();
    let sizes = scheme.sizes();
    println!("{} sizes:", scheme.algorithm_name());
    println!("  Backend: {}", scheme.backend_name());
    println!("  Param set: {}", scheme.param_set_name());
    println!("  Public key: {} bytes", sizes.public_key_bytes);
    println!("  Secret key: {} bytes", sizes.secret_key_bytes);
    println!("  Signature: {} bytes", sizes.signature_bytes);
}

fn print_memory_usage() {
    let scheme = checked_scheme();
    let id = default_identifier();
    println!("{} peak heap usage:", scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let (_public_key, mut secret_key) = scheme.keypair_with_seed(
            LMOTS_Q,
            id,
            seed_bytes_from_u64(seed_from_str(&format!(
                "lm-ots-divan-mem-sign-key-{message_size}"
            ))),
        );
        let _signature = scheme
            .sign_with_seed(
                &message,
                &mut secret_key,
                seed_from_str(&format!("lm-ots-divan-mem-sign-{message_size}")),
            )
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        let (public_key, mut verify_secret_key) = scheme.keypair_with_seed(
            LMOTS_Q,
            id,
            seed_bytes_from_u64(seed_from_str(&format!(
                "lm-ots-divan-mem-verify-key-{message_size}"
            ))),
        );
        let verify_signature = scheme
            .sign_with_seed(
                &message,
                &mut verify_secret_key,
                seed_from_str(&format!(
                    "lm-ots-divan-mem-verify-sign-{message_size}"
                )),
            )
            .expect("memory measurement should sign verify message");
        memory::reset_peak();
        let valid = scheme
            .verify(&message, &verify_signature, &public_key)
            .expect("memory measurement verify call should succeed");
        assert!(valid, "benchmark setup should verify the signed message");
        let verify_peak = memory::peak_bytes();

        println!(
            "  Message {} bytes: sign={} bytes, verify={} bytes",
            message_size, sign_peak, verify_peak
        );
    }
}

fn checked_scheme() -> LmOtsScheme {
    let scheme = LmOtsScheme::new(LmOtsParamSet::Sha256N32W4);
    assert_eq!(
        scheme.algorithm_name(),
        EXPECTED_ALGORITHM,
        "unexpected algorithm in lm_ots benchmark"
    );
    assert_eq!(
        scheme.backend_name(),
        EXPECTED_BACKEND,
        "unexpected backend in lm_ots benchmark"
    );
    assert_eq!(
        scheme.param_set_name(),
        EXPECTED_PARAM_SET,
        "unexpected parameter set in lm_ots benchmark"
    );
    scheme
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
