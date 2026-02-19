use divan::{black_box, AllocProfiler, Bencher};
use std::sync::atomic::{AtomicU64, Ordering};
use winternitz_ots::{
    bench_message, memory, SignatureScheme, TrackingAllocator,
    BENCH_MESSAGE_SIZES, WINTERNITZ_OTS,
};

const EXPECTED_ALGORITHM: &str = "Winternitz OTS (W-OTS)";
const EXPECTED_BACKEND: &str = "winternitz-ots-0.3.0";
const EXPECTED_PARAM_SET: &str = "w=16,n=32,hash=blake2b";

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = checked_scheme();
    bencher.bench(|| {
        black_box(scheme.keypair());
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = checked_scheme();
    let message = bench_message(message_size);
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    bencher.bench(|| {
        let _i = COUNTER.fetch_add(1, Ordering::Relaxed);
        let keypair = scheme.keypair();
        black_box(scheme.sign(black_box(&keypair), black_box(&message)));
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = checked_scheme();
    let message = bench_message(message_size);
    let keypair = scheme.keypair();
    let signature = scheme.sign(&keypair, &message);

    bencher.bench(|| {
        let verified = scheme.verify(black_box(&signature));
        assert!(verified, "winternitz verify benchmark input should verify");
        black_box(verified);
    });
}

fn print_sizes() {
    let scheme = checked_scheme();
    let keypair = scheme.keypair();
    println!("{} sizes:", scheme.algorithm_name());
    println!("  Backend: {}", scheme.backend_name());
    println!("  Param set: {}", scheme.param_set_name());
    println!("  Public key: {} bytes", scheme.public_key_size(&keypair));
    println!("  Secret key: {} bytes", scheme.secret_key_size(&keypair));

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = scheme.sign(&keypair, &message);
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            scheme.signature_size(&signature)
        );
    }
}

fn print_memory_usage() {
    let scheme = checked_scheme();
    println!("{} peak heap usage:", scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let keypair = scheme.keypair();
        let signature = scheme.sign(&keypair, &message);
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let verified = scheme.verify(&signature);
        assert!(verified, "benchmark setup should verify the signed message");
        let verify_peak = memory::peak_bytes();

        println!(
            "  Message {} bytes: sign={} bytes, verify={} bytes",
            message_size, sign_peak, verify_peak
        );
    }
}

fn checked_scheme() -> winternitz_ots::WinternitzOtsScheme {
    let scheme = WINTERNITZ_OTS;
    assert_eq!(
        scheme.algorithm_name(),
        EXPECTED_ALGORITHM,
        "unexpected algorithm in winternitz_ots benchmark"
    );
    assert_eq!(
        scheme.backend_name(),
        EXPECTED_BACKEND,
        "unexpected backend in winternitz_ots benchmark"
    );
    assert_eq!(
        scheme.param_set_name(),
        EXPECTED_PARAM_SET,
        "unexpected parameter set in winternitz_ots benchmark"
    );
    scheme
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
