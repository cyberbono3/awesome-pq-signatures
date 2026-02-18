use divan::{black_box, AllocProfiler, Bencher};
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use sphincs_plus::{
    bench_message, memory, signature_size, SignatureScheme, TrackingAllocator,
    BENCH_MESSAGE_SIZES, SPHINCS_PLUS_SHAKE_128F_SIMPLE,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
    bencher.bench(|| {
        black_box(scheme.keypair());
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
    let message = bench_message(message_size);
    let (_, secret_key) = scheme.keypair();

    bencher.bench(|| {
        black_box(
            scheme.sign(black_box(message.as_slice()), black_box(&secret_key)),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
    let message = bench_message(message_size);
    let (public_key, secret_key) = scheme.keypair();
    let signed_message = scheme.sign(&message, &secret_key);

    bencher.bench(|| {
        let opened = scheme
            .open(black_box(&signed_message), black_box(&public_key))
            .expect("sphincs+ verify benchmark input should always be valid");
        black_box(opened);
    });
}

fn print_sizes() {
    let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
    let (public_key, secret_key) = scheme.keypair();
    println!("{} sizes:", scheme.algorithm_name());
    println!("  Public key: {} bytes", public_key.as_bytes().len());
    println!("  Secret key: {} bytes", secret_key.as_bytes().len());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signed_message = scheme.sign(&message, &secret_key);
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            signature_size(&signed_message, message.len())
        );
    }
}

fn print_memory_usage() {
    let scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE;
    println!("{} peak heap usage:", scheme.algorithm_name());
    let (public_key, secret_key) = scheme.keypair();

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signed_message = scheme.sign(&message, &secret_key);
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _opened = scheme
            .open(&signed_message, &public_key)
            .expect("benchmark setup should verify the signed message");
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
