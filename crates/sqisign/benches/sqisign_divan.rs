use divan::{black_box, AllocProfiler, Bencher};
use sqisign::{
    bench_message, memory, TrackingAllocator, BENCH_MESSAGE_SIZES, SQISIGN,
};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = SQISIGN;

    bencher.bench(|| {
        black_box(scheme.keypair().expect("key generation should succeed"));
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = SQISIGN;
    let keypair = scheme.keypair().expect("key generation should succeed");
    let message = bench_message(message_size);

    bencher.bench(|| {
        black_box(
            scheme
                .sign(black_box(&keypair), black_box(&message))
                .expect("sqisign sign benchmark input should always be valid"),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = SQISIGN;
    let keypair = scheme.keypair().expect("key generation should succeed");
    let message = bench_message(message_size);
    let signature = scheme
        .sign(&keypair, &message)
        .expect("benchmark setup should sign message");

    bencher.bench(|| {
        black_box(
            scheme
                .verify(
                    black_box(&keypair),
                    black_box(&message),
                    black_box(&signature),
                )
                .expect("verification should succeed"),
        );
    });
}

fn print_sizes() {
    let scheme = SQISIGN;
    let keypair = scheme.keypair().expect("key generation should succeed");
    println!("{} sizes:", scheme.algorithm_name());
    println!("  Public key: {} bytes", scheme.public_key_size(&keypair));
    println!("  Secret key: {} bytes", scheme.secret_key_size(&keypair));

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = scheme
            .sign(&keypair, &message)
            .expect("size measurement should sign message");
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            scheme.signature_size(&signature)
        );
    }
}

fn print_memory_usage() {
    let scheme = SQISIGN;
    let keypair = scheme.keypair().expect("key generation should succeed");
    println!("{} peak heap usage:", scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = scheme
            .sign(&keypair, &message)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = scheme
            .verify(&keypair, &message, &signature)
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
