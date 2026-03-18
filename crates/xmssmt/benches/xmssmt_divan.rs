use divan::Bencher;
use xmssmt_bench::{XmssmtParamSet, XmssmtScheme};

fn main() {
    divan::main();
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);

    bencher.bench(|| {
        let kp = scheme.keypair().expect("xmssmt keypair must succeed");
        std::hint::black_box(kp);
    });
}

#[divan::bench(args = [32_usize, 1024_usize])]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);
    let message = vec![0x3C; message_size];

    bencher.bench(|| {
        let mut kp = scheme.keypair().expect("xmssmt keypair must succeed");
        let signature = kp.sign(&message).expect("xmssmt sign must succeed");
        std::hint::black_box(signature);
    });
}

#[divan::bench(args = [32_usize, 1024_usize])]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = XmssmtScheme::new(XmssmtParamSet::Sha2_20_2_256);
    let message = vec![0x3C; message_size];
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
