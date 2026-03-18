use divan::{black_box, AllocProfiler, Bencher};
use sqisign::{
    bench_message, memory, SqisignKeyPair, SqisignSignature, TrackingAllocator,
    BENCH_MESSAGE_SIZES, SQISIGN,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> = TrackingAllocator::new(&DIVAN_ALLOC);

fn benchmark_keypair() -> SqisignKeyPair {
    SQISIGN
        .benchmark_keypair()
        .expect("key generation should succeed")
}

fn signed_fixture(message_size: usize) -> (SqisignKeyPair, Vec<u8>, SqisignSignature) {
    let keypair = benchmark_keypair();
    let message = bench_message(message_size);
    let signature = SQISIGN
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
            SQISIGN
                .sign_message(black_box(&keypair), black_box(&message))
                .expect("sqisign sign benchmark input should always be valid"),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let (keypair, message, signature) = signed_fixture(message_size);

    bencher.bench(|| {
        black_box(
            SQISIGN
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
    println!("{} sizes:", SQISIGN.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = SQISIGN
            .sign_message(&keypair, &message)
            .expect("size measurement should sign message");
        let sizes = SQISIGN.sizes(&keypair, &signature);
        if message_size == BENCH_MESSAGE_SIZES[0] {
            println!("  Public key: {} bytes", sizes.public_key);
            println!("  Secret key: {} bytes", sizes.secret_key);
        }
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size, sizes.signature
        );
    }
}

fn print_memory_usage() {
    let keypair = benchmark_keypair();
    println!("{} peak heap usage:", SQISIGN.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = SQISIGN
            .sign_message(&keypair, &message)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = SQISIGN
            .verify_message(&keypair, &message, &signature)
            .expect("verification should succeed");
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
