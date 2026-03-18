use divan::Bencher;
use xmssmt_bench::{
    benchmark_message, default_benchmark_scheme, DIVAN_BENCH_MESSAGE_SIZES,
};

fn main() {
    divan::main();
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = default_benchmark_scheme();

    bencher.bench(|| {
        let kp = scheme.keypair().expect("xmssmt keypair must succeed");
        std::hint::black_box(kp);
    });
}

#[divan::bench(args = DIVAN_BENCH_MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = default_benchmark_scheme();
    let message = benchmark_message(message_size, 0x3C);

    bencher.bench(|| {
        let mut kp = scheme.keypair().expect("xmssmt keypair must succeed");
        let signature = kp.sign(&message).expect("xmssmt sign must succeed");
        std::hint::black_box(signature);
    });
}

#[divan::bench(args = DIVAN_BENCH_MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = default_benchmark_scheme();
    let message = benchmark_message(message_size, 0x3C);
    let mut kp = scheme.keypair().expect("xmssmt keypair must succeed");
    let signature = kp.sign(&message).expect("xmssmt sign must succeed");

    bencher.bench(|| {
        let is_valid = kp
            .verify(&message, &signature)
            .expect("xmssmt verify call must succeed");
        assert!(is_valid, "xmssmt verify must be true");
        std::hint::black_box(is_valid);
    });
}
