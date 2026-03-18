use divan::Bencher;
use xmss_bench::{
    benchmark_message, default_benchmark_scheme, DIVAN_BENCH_MESSAGE_SIZES,
};

fn main() {
    divan::main();
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = default_benchmark_scheme();

    bencher.bench(|| {
        let keypair = scheme.keypair().expect("xmss keypair must succeed");
        std::hint::black_box(keypair);
    });
}

#[divan::bench(args = DIVAN_BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = default_benchmark_scheme();
    let message = benchmark_message(message_size, 0x3C);

    bencher.bench(|| {
        let (_, mut secret_key) = scheme.keypair().expect("xmss keypair must succeed");
        let signature = scheme
            .sign(&message, &mut secret_key)
            .expect("xmss sign must succeed");
        std::hint::black_box(signature);
    });
}

#[divan::bench(args = DIVAN_BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = default_benchmark_scheme();
    let message = benchmark_message(message_size, 0x3C);
    let (public_key, mut secret_key) = scheme.keypair().expect("xmss keypair must succeed");
    let signature = scheme
        .sign(&message, &mut secret_key)
        .expect("xmss sign must succeed");

    bencher.bench(|| {
        let is_valid = scheme
            .verify(&message, &signature, &public_key)
            .expect("xmss verify call must succeed");
        assert!(is_valid, "xmss verify must be true");
        std::hint::black_box(is_valid);
    });
}
