use divan::{black_box, AllocProfiler, Bencher};
use mayo::{
    bench_message, memory, signed_message_size, TrackingAllocator,
    BENCH_MESSAGE_SIZES, MAYO,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

fn benchmark_keypair() -> mayo::MayoKeyPair {
    MAYO.benchmark_keypair()
}

fn signed_fixture(
    message_size: usize,
) -> (mayo::MayoKeyPair, Vec<u8>, mayo::MayoSignature) {
    let scheme = MAYO;
    let keypair = benchmark_keypair();
    let message = bench_message(message_size);
    let signature = scheme
        .sign_message(&keypair, &message)
        .expect("benchmark setup should sign message");
    (keypair, message, signature)
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    bencher.bench(|| {
        black_box(benchmark_keypair());
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = MAYO;
    let keypair = benchmark_keypair();
    let message = bench_message(message_size);

    bencher.bench(|| {
        black_box(
            scheme
                .sign_message(black_box(&keypair), black_box(&message))
                .expect("mayo sign benchmark input should always be valid"),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = MAYO;
    let (keypair, message, signature) = signed_fixture(message_size);

    bencher.bench(|| {
        black_box(scheme.verify_message(
            black_box(&keypair),
            black_box(&message),
            black_box(&signature),
        ));
    });
}

fn print_sizes() {
    let scheme = MAYO;
    let keypair = benchmark_keypair();
    println!("{} sizes:", scheme.algorithm_name());
    println!("  Public key: {} bytes", scheme.public_key_size(&keypair));
    println!("  Secret key: {} bytes", scheme.secret_key_size(&keypair));

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = scheme
            .sign_message(&keypair, &message)
            .expect("size measurement should sign message");
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            scheme.signature_size(&signature)
        );
        println!(
            "  Signed message size (message {} bytes): {} bytes",
            message_size,
            signed_message_size(
                message_size,
                scheme.signature_size(&signature)
            )
        );
    }
}

fn print_memory_usage() {
    let scheme = MAYO;
    let keypair = benchmark_keypair();
    println!("{} peak heap usage:", scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = scheme
            .sign_message(&keypair, &message)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = scheme.verify_message(&keypair, &message, &signature);
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
