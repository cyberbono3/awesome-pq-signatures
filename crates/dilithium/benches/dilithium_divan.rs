use dilithium::{
    bench_message, default_seed, memory, SignatureScheme, TrackingAllocator,
    BENCH_MESSAGE_SIZES, ML_DSA_65,
};
use divan::{black_box, AllocProfiler, Bencher};

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();

#[global_allocator]
static ALLOC: TrackingAllocator<AllocProfiler> =
    TrackingAllocator::new(&DIVAN_ALLOC);

const CONTEXT: &[u8] = &[];

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = ML_DSA_65;
    let seed = default_seed();

    bencher.bench(|| {
        black_box(scheme.keypair(black_box(&seed)));
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = ML_DSA_65;
    let seed = default_seed();
    let keypair = scheme.keypair(&seed);
    let message = bench_message(message_size);

    bencher.bench(|| {
        black_box(
            scheme
                .sign(
                    black_box(&keypair),
                    black_box(&message),
                    black_box(CONTEXT),
                )
                .expect(
                    "dilithium sign benchmark input should always be valid",
                ),
        );
    });
}

#[divan::bench(args = BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = ML_DSA_65;
    let seed = default_seed();
    let keypair = scheme.keypair(&seed);
    let message = bench_message(message_size);
    let signature = scheme
        .sign(&keypair, &message, CONTEXT)
        .expect("benchmark setup should sign message");

    bencher.bench(|| {
        black_box(scheme.verify(
            black_box(&keypair),
            black_box(&message),
            black_box(CONTEXT),
            black_box(&signature),
        ));
    });
}

fn print_sizes() {
    let scheme = ML_DSA_65;
    let seed = default_seed();
    let keypair = scheme.keypair(&seed);
    println!("{} sizes:", scheme.algorithm_name());
    println!("  Public key: {} bytes", scheme.public_key_size(&keypair));
    println!("  Secret key: {} bytes", scheme.secret_key_size(&keypair));

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);
        let signature = scheme
            .sign(&keypair, &message, CONTEXT)
            .expect("size measurement should sign message");
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            scheme.signature_size(&signature)
        );
    }
}

fn print_memory_usage() {
    let scheme = ML_DSA_65;
    let seed = default_seed();
    let keypair = scheme.keypair(&seed);
    println!("{} peak heap usage:", scheme.algorithm_name());

    for message_size in BENCH_MESSAGE_SIZES {
        let message = bench_message(message_size);

        memory::reset_peak();
        let signature = scheme
            .sign(&keypair, &message, CONTEXT)
            .expect("memory measurement should sign message");
        let sign_peak = memory::peak_bytes();

        memory::reset_peak();
        let _verified = scheme.verify(&keypair, &message, CONTEXT, &signature);
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
