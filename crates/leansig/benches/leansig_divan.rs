use divan::{black_box, Bencher};
use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::MESSAGE_LENGTH;
use leansig_bench::{prepare_sk_for_epoch, SelectedLeanSigScheme, BENCH_MESSAGE};

type Scheme = SelectedLeanSigScheme;

const EPOCH: u32 = 1;

fn bench_message() -> [u8; MESSAGE_LENGTH] {
    let mut message = [0u8; MESSAGE_LENGTH];
    let copy_len = BENCH_MESSAGE.len().min(MESSAGE_LENGTH);
    message[..copy_len].copy_from_slice(&BENCH_MESSAGE[..copy_len]);
    message
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    bencher.bench(|| {
        let mut rng = rand::rng();
        let kp = Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize);
        black_box(kp);
    });
}

#[divan::bench]
fn sign(bencher: Bencher) {
    let message = bench_message();

    bencher
        .with_inputs(|| {
            let mut rng = rand::rng();
            let (pk, mut sk) = Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize);
            prepare_sk_for_epoch(&mut sk, EPOCH);
            (pk, sk)
        })
        .bench_values(|(_pk, sk)| {
            black_box(
                Scheme::sign(&sk, EPOCH, black_box(&message))
                    .expect("leansig sign benchmark should succeed"),
            );
        });
}

#[divan::bench]
fn verify(bencher: Bencher) {
    let message = bench_message();
    let mut rng = rand::rng();
    let (pk, mut sk) = Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize);
    prepare_sk_for_epoch(&mut sk, EPOCH);
    let sig = Scheme::sign(&sk, EPOCH, &message).expect("setup sign should succeed");

    bencher.bench(|| {
        let valid = Scheme::verify(
            black_box(&pk),
            black_box(EPOCH),
            black_box(&message),
            black_box(&sig),
        );
        assert!(valid, "signature should verify");
        black_box(valid);
    });
}

fn print_sizes() {
    let mut rng = rand::rng();
    let (pk, mut sk) = Scheme::key_gen(&mut rng, 0, Scheme::LIFETIME as usize);
    prepare_sk_for_epoch(&mut sk, EPOCH);
    let message = bench_message();
    let sig = Scheme::sign(&sk, EPOCH, &message).expect("size sign should succeed");

    println!("LeanSig sizes:");
    println!("  Public key: {} bytes", pk.to_bytes().len());
    println!("  Secret key: {} bytes", sk.to_bytes().len());
    println!("  Signature:  {} bytes", sig.to_bytes().len());
}

fn main() {
    print_sizes();
    divan::main();
}
