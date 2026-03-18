use cross::{
    bench_message, memory, CrossKeyPair, CrossSignature, TrackingAllocator, BENCH_MESSAGE_SIZES,
    CROSS,
};
use divan::{black_box, AllocProfiler, Bencher};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> = TrackingAllocator::new(&DIVAN_ALLOC);

fn benchmark_keypair() -> CrossKeyPair {
    CROSS
        .benchmark_keypair()
        .expect("key generation should succeed")
}

fn signed_fixture(message_size: usize) -> (CrossKeyPair, Vec<u8>, CrossSignature) {
    let keypair = benchmark_keypair();
    let message = bench_message(message_size);
    let signature = CROSS
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
    let keypair = benchmark_keypair();
    println!("{} sizes:", CROSS.algorithm_name());
    println!("  Public key: {} bytes", CROSS.public_key_size(&keypair));
    println!("  Secret key: {} bytes", CROSS.secret_key_size(&keypair));

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = CROSS
            .sign_message(&keypair, &message)
            .expect("size measurement should sign message");
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            CROSS.signature_size(&signature)
        );
    }
}

fn print_memory_usage() {
    let keypair = benchmark_keypair();
    println!("{} peak heap usage:", CROSS.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = CROSS
            .sign_message(&keypair, &message)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = CROSS
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
