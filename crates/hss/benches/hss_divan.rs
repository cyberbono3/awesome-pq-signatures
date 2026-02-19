use divan::{black_box, AllocProfiler, Bencher};
use hss::{
    bench_message, default_seed, memory, signed_message_size, HssScheme,
    TrackingAllocator, BENCH_MESSAGE_SIZES, DEFAULT_PARAM_SET_NAME,
    HSS_PARAM_SETS,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

const PARAM_SET_NAMES: [&str; 2] =
    ["HSS-SHA256-H5-W2-L1", "HSS-SHA256-H5-W2-L2"];

#[divan::bench(args = PARAM_SET_NAMES)]
fn keygen(bencher: Bencher, param_set_name: &'static str) {
    let scheme = HssScheme::from_param_set_name(param_set_name)
        .expect("known HSS param set");
    let seed = default_seed();

    bencher.bench(|| {
        black_box(
            scheme
                .keypair_with_seed(black_box(seed))
                .expect("HSS key generation should succeed"),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign_l1(bencher: Bencher, message_size: usize) {
    sign_bench(bencher, "HSS-SHA256-H5-W2-L1", message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign_l2(bencher: Bencher, message_size: usize) {
    sign_bench(bencher, "HSS-SHA256-H5-W2-L2", message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify_l1(bencher: Bencher, message_size: usize) {
    verify_bench(bencher, "HSS-SHA256-H5-W2-L1", message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify_l2(bencher: Bencher, message_size: usize) {
    verify_bench(bencher, "HSS-SHA256-H5-W2-L2", message_size);
}

fn sign_bench(
    bencher: Bencher,
    param_set_name: &'static str,
    message_size: usize,
) {
    let scheme = HssScheme::from_param_set_name(param_set_name)
        .expect("known HSS param set");
    let message = bench_message(message_size);
    let seed = default_seed();

    bencher
        .with_inputs(|| {
            scheme
                .keypair_with_seed(seed)
                .expect("input generation should produce a keypair")
                .1
        })
        .bench_values(|mut secret_key| {
            black_box(
                scheme
                    .sign(black_box(&message), &mut secret_key)
                    .expect("HSS sign benchmark should succeed"),
            );
        });
}

fn verify_bench(
    bencher: Bencher,
    param_set_name: &'static str,
    message_size: usize,
) {
    let scheme = HssScheme::from_param_set_name(param_set_name)
        .expect("known HSS param set");
    let message = bench_message(message_size);
    let (public_key, mut secret_key) = scheme
        .keypair_with_seed(default_seed())
        .expect("setup keypair should succeed");
    let signature = scheme
        .sign(&message, &mut secret_key)
        .expect("setup signature should succeed");

    bencher.bench(|| {
        let verified = scheme
            .verify(
                black_box(&message),
                black_box(&signature),
                black_box(&public_key),
            )
            .expect("verify benchmark should execute");
        assert!(verified, "signature should verify");
        black_box(verified);
    });
}

fn print_sizes() {
    println!("HSS sizes:");
    for param_set in HSS_PARAM_SETS {
        let scheme = HssScheme::new(param_set);
        let (public_key, mut secret_key) = scheme
            .keypair_with_seed(default_seed())
            .expect("size keygen should succeed");
        let signature = scheme
            .sign(&bench_message(32), &mut secret_key)
            .expect("size sign should succeed");
        let key_lifetime = secret_key
            .lifetime()
            .expect("size lifetime query should succeed");

        println!("  Param set: {}", param_set.name());
        println!(
            "    Public key: {} bytes",
            scheme.public_key_size(&public_key)
        );
        println!(
            "    Secret key: {} bytes",
            scheme.secret_key_size(&secret_key)
        );
        println!(
            "    Signature (message 32 bytes): {} bytes",
            scheme.signature_size(&signature)
        );
        println!(
            "    Signed message size (32-byte message): {} bytes",
            signed_message_size(32, scheme.signature_size(&signature))
        );
        println!("    Estimated signatures per key: {key_lifetime}");
    }
}

fn print_memory_usage() {
    let scheme = HssScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
        .expect("default HSS parameter set should exist");
    println!("{} peak heap usage:", scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let (public_key, mut secret_key) = scheme
            .keypair_with_seed(default_seed())
            .expect("memory setup keygen should succeed");

        memory::reset_peak();
        let signature = scheme
            .sign(&message, &mut secret_key)
            .expect("memory sign should succeed");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = scheme
            .verify(&message, &signature, &public_key)
            .expect("memory verify should execute");
        let verify_peak = memory::peak_bytes();

        println!(
            "  Message {} bytes: sign={} bytes, verify={} bytes",
            message_size, sign_peak, verify_peak
        );
    }
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
