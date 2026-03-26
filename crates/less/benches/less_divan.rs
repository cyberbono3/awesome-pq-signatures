use divan::{black_box, Bencher};
use less::{
    bench_message, memory, LessKeyPair, LessSignature, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE_SIZES, LESS,
};
use pq_bench::{print_signed_message_memory_usage, print_signed_message_sizes};
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
    pq_bench::signed_fixture(
        message_size,
        benchmark_keypair,
        |keypair, message| {
            LESS.sign_message(keypair, message)
                .expect("benchmark setup should sign message")
        },
    )
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
    print_signed_message_sizes(
        LESS.algorithm_name(),
        &BENCH_MESSAGE_SIZES,
        benchmark_keypair,
        |keypair| LESS.public_key_size(keypair),
        |keypair| LESS.secret_key_size(keypair),
        |keypair, message| {
            LESS.sign_message(keypair, message)
                .expect("size measurement should sign message")
        },
        |signature| LESS.signature_size(signature),
    );
}

fn print_memory_usage() {
    print_signed_message_memory_usage(
        LESS.algorithm_name(),
        &BENCH_MESSAGE_SIZES,
        benchmark_keypair,
        |keypair, message| {
            LESS.sign_message(keypair, message)
                .expect("memory measurement should sign message")
        },
        |keypair, message, signature| {
            let _verified = LESS
                .verify_message(keypair, message, signature)
                .expect("verification should succeed");
        },
        memory::reset_peak,
        memory::peak_bytes,
    );
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
