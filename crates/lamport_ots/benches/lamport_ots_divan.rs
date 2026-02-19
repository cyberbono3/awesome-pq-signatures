use divan::Bencher;
use lamport_ots::{seed_from_str, LamportOtsScheme};
use std::sync::atomic::{AtomicU64, Ordering};

fn main() {
    divan::main();
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = LamportOtsScheme;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seed_base = seed_from_str("lamport-divan-keygen");

    bencher.bench(|| {
        let seed = seed_base ^ COUNTER.fetch_add(1, Ordering::Relaxed);
        let keypair = scheme.keypair_with_seed(seed);
        std::hint::black_box(keypair);
    });
}

#[divan::bench(args = [32_usize, 1024_usize])]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = LamportOtsScheme;
    let mut message = vec![0_u8; message_size];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seed_base = seed_from_str("lamport-divan-sign");

    bencher.bench(|| {
        let seed = seed_base ^ COUNTER.fetch_add(1, Ordering::Relaxed);
        let (_, mut secret_key) = scheme.keypair_with_seed(seed);
        let signature = scheme
            .sign(&message, &mut secret_key)
            .expect("lamport sign should succeed");
        std::hint::black_box(signature);
    });
}

#[divan::bench(args = [32_usize, 1024_usize])]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = LamportOtsScheme;
    let mut message = vec![0_u8; message_size];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }

    let (public_key, mut secret_key) =
        scheme.keypair_with_seed(seed_from_str("lamport-divan-verify"));
    let signature = scheme
        .sign(&message, &mut secret_key)
        .expect("lamport sign should succeed");

    bencher.bench(|| {
        let is_valid = scheme
            .verify(&message, &signature, &public_key)
            .expect("lamport verify call should succeed");
        assert!(is_valid, "lamport verify must return true");
        std::hint::black_box(is_valid);
    });
}
