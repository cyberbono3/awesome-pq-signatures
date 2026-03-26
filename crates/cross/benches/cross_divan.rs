use cross::{
    bench_message, memory, CrossKeyPair, CrossSignature, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE_SIZES, CROSS,
};
use divan::{black_box, Bencher};
use pq_bench::{print_signed_message_memory_usage, print_signed_message_sizes};
pq_bench::install_divan_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn benchmark_keypair() -> CrossKeyPair {
    CROSS
        .benchmark_keypair()
        .expect("key generation should succeed")
}

fn signed_fixture(
    message_size: usize,
) -> (CrossKeyPair, Vec<u8>, CrossSignature) {
    pq_bench::signed_fixture(
        message_size,
        benchmark_keypair,
        |keypair, message| {
            CROSS
                .sign_message(keypair, message)
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
            CROSS
                .sign_message(black_box(&keypair), black_box(&message))
                .expect("cross sign benchmark input should always be valid"),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let (keypair, message, signature) = signed_fixture(message_size);

    bencher.bench(|| {
        black_box(
            CROSS
                .verify_message(
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
        CROSS.algorithm_name(),
        &BENCH_MESSAGE_SIZES,
        benchmark_keypair,
        |keypair| CROSS.public_key_size(keypair),
        |keypair| CROSS.secret_key_size(keypair),
        |keypair, message| {
            CROSS
                .sign_message(keypair, message)
                .expect("size measurement should sign message")
        },
        |signature| CROSS.signature_size(signature),
    );
}

fn print_memory_usage() {
    print_signed_message_memory_usage(
        CROSS.algorithm_name(),
        &BENCH_MESSAGE_SIZES,
        benchmark_keypair,
        |keypair, message| {
            CROSS
                .sign_message(keypair, message)
                .expect("memory measurement should sign message")
        },
        |keypair, message, signature| {
            let _verified = CROSS
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
