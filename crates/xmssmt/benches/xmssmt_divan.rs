use divan::{black_box, AllocProfiler, Bencher};
use xmssmt::{
    bench_message, memory, TrackingAllocator, XmssmtScheme,
    BENCH_MESSAGE_SIZES, DEFAULT_PARAM_SET_NAME, XMSSMT_L1_NAME,
    XMSSMT_L3_NAME, XMSSMT_L5_NAME, XMSSMT_PARAM_SETS,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

const PARAM_SET_NAMES: [&str; 3] =
    [XMSSMT_L1_NAME, XMSSMT_L3_NAME, XMSSMT_L5_NAME];

#[divan::bench(args = PARAM_SET_NAMES)]
fn keygen(bencher: Bencher, param_set_name: &'static str) {
    let scheme = XmssmtScheme::from_param_set_name(param_set_name)
        .expect("known XMSSMT param set");

    bencher.bench(|| {
        black_box(scheme.keypair());
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign_l1(bencher: Bencher, message_size: usize) {
    sign_bench(bencher, XMSSMT_L1_NAME, message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign_l3(bencher: Bencher, message_size: usize) {
    sign_bench(bencher, XMSSMT_L3_NAME, message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign_l5(bencher: Bencher, message_size: usize) {
    sign_bench(bencher, XMSSMT_L5_NAME, message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify_l1(bencher: Bencher, message_size: usize) {
    verify_bench(bencher, XMSSMT_L1_NAME, message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify_l3(bencher: Bencher, message_size: usize) {
    verify_bench(bencher, XMSSMT_L3_NAME, message_size);
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify_l5(bencher: Bencher, message_size: usize) {
    verify_bench(bencher, XMSSMT_L5_NAME, message_size);
}

fn sign_bench(
    bencher: Bencher,
    param_set_name: &'static str,
    message_size: usize,
) {
    let scheme = XmssmtScheme::from_param_set_name(param_set_name)
        .expect("known XMSSMT param set");
    let message = bench_message(message_size);
    let (_, mut secret_key) = scheme.keypair();

    bencher.bench_local(|| {
        let signature = scheme
            .sign(black_box(&message), black_box(&mut secret_key))
            .expect("xmssmt sign benchmark input should always be valid");
        black_box(signature);
    });
}

fn verify_bench(
    bencher: Bencher,
    param_set_name: &'static str,
    message_size: usize,
) {
    let scheme = XmssmtScheme::from_param_set_name(param_set_name)
        .expect("known XMSSMT param set");
    let message = bench_message(message_size);
    let (public_key, mut secret_key) = scheme.keypair();
    let signature = scheme
        .sign(&message, &mut secret_key)
        .expect("benchmark setup should sign message");

    bencher.bench(|| {
        let verified = scheme
            .verify(
                black_box(&message),
                black_box(&signature),
                black_box(&public_key),
            )
            .expect("xmssmt verify benchmark input should be valid");
        assert!(verified, "xmssmt verify must return true");
        black_box(verified);
    });
}

fn print_sizes() {
    println!("XMSSMT sizes:");
    for param_set in XMSSMT_PARAM_SETS {
        let scheme = XmssmtScheme::new(param_set);
        let (public_key, secret_key) = scheme.keypair();
        let (_public_key_for_sig, mut secret_key_for_sig) = scheme.keypair();
        let signature = scheme
            .sign(&bench_message(32), &mut secret_key_for_sig)
            .expect("size measurement should sign");

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
    }
}

fn print_memory_usage() {
    let default_scheme =
        XmssmtScheme::from_param_set_name(DEFAULT_PARAM_SET_NAME)
            .expect("default param set should exist");
    println!("{} peak heap usage:", default_scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let (public_key, mut secret_key) = default_scheme.keypair();

        memory::reset_peak();
        let signature = default_scheme
            .sign(&message, &mut secret_key)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = default_scheme
            .verify(&message, &signature, &public_key)
            .expect("memory measurement should verify message");
        let verify_peak = memory::peak_bytes();

        println!(
            "  Param {DEFAULT_PARAM_SET_NAME}, message {message_size} bytes: sign={} bytes, verify={} bytes",
            sign_peak, verify_peak
        );
    }
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
