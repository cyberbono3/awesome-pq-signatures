use divan::{black_box, AllocProfiler, Bencher};
use sphincs::{
    bench_message, memory, SignatureScheme, TrackingAllocator,
    BENCH_MESSAGE_SIZES, SPHINCS_SCHEME,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = SPHINCS_SCHEME;
    bencher.bench(|| {
        black_box(scheme.keypair());
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = SPHINCS_SCHEME;
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
    let scheme = SPHINCS_SCHEME;
    let message = bench_message(message_size);
    let (public_key, secret_key) = scheme.keypair();
    let signature = scheme.sign(&message, &secret_key);

    bencher.bench(|| {
        black_box(scheme.verify(
            black_box(&message),
            black_box(&signature),
            black_box(&public_key),
        ));
    });
}

fn print_sizes() {
    let scheme = SPHINCS_SCHEME;
    let (public_key, secret_key) = scheme.keypair();
    println!("{} sizes:", scheme.algorithm_name());
    println!(
        "  Public key: {} bytes",
        scheme.public_key_size(&public_key)
    );
    println!(
        "  Secret key: {} bytes",
        scheme.secret_key_size(&secret_key)
    );

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = scheme.sign(&message, &secret_key);
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            scheme.signature_size(&signature)
        );
    }
}

fn print_memory_usage() {
    let scheme = SPHINCS_SCHEME;
    println!("{} peak heap usage:", scheme.algorithm_name());
    let (public_key, secret_key) = scheme.keypair();

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = scheme.sign(&message, &secret_key);
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = scheme.verify(&message, &signature, &public_key);
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
