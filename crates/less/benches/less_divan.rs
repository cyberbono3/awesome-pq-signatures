use divan::{black_box, Bencher};
use less::{
    bench_message, memory, LessKeyPair, LessSignature, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE_SIZES, LESS,
};
pq_bench::install_divan_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn benchmark_keypair() -> LessKeyPair {
    LESS.benchmark_keypair()
        .expect("key generation should succeed")
}

fn signed_fixture(
    message_size: usize,
) -> (LessKeyPair, Vec<u8>, LessSignature) {
    let keypair = benchmark_keypair();
    let message = bench_message(message_size);
    let signature = LESS
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
    let keypair = benchmark_keypair();
    let message = bench_message(message_size);

    bencher.bench(|| {
        black_box(
            LESS.sign_message(black_box(&keypair), black_box(&message))
                .expect("less sign benchmark input should always be valid"),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let (keypair, message, signature) = signed_fixture(message_size);

    bencher.bench(|| {
        black_box(
            LESS.verify_message(
                black_box(&keypair),
                black_box(&message),
                black_box(&signature),
            )
            .expect("verification should succeed"),
        );
    });
}

fn print_sizes() {
    let keypair = benchmark_keypair();
    println!("{} sizes:", LESS.algorithm_name());
    println!("  Public key: {} bytes", LESS.public_key_size(&keypair));
    println!("  Secret key: {} bytes", LESS.secret_key_size(&keypair));

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = LESS
            .sign_message(&keypair, &message)
            .expect("size measurement should sign message");
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            LESS.signature_size(&signature)
        );
    }
}

fn print_memory_usage() {
    let keypair = benchmark_keypair();
    println!("{} peak heap usage:", LESS.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = LESS
            .sign_message(&keypair, &message)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = LESS
            .verify_message(&keypair, &message, &signature)
            .expect("verification should succeed");
        let verify_peak = memory::peak_bytes();

        println!(
            "  Message {message_size} bytes: sign={sign_peak} bytes, verify={verify_peak} bytes"
        );
    }
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
