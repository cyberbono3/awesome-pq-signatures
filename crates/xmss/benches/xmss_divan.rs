use divan::Bencher;
use xmss::{XmssParamSet, XmssScheme};

fn main() {
    divan::main();
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    let scheme = XmssScheme::new(XmssParamSet::XmssSha2_10_256);

    bencher.bench(|| {
        let keypair = scheme.keypair().expect("xmss keypair must succeed");
        std::hint::black_box(keypair);
    });
}

#[divan::bench(args = [32_usize, 1024_usize])]
fn sign(bencher: Bencher, message_size: usize) {
    let scheme = XmssScheme::new(XmssParamSet::XmssSha2_10_256);
    let message = vec![0x3C; message_size];

    bencher.bench(|| {
        let (_, mut secret_key) =
            scheme.keypair().expect("xmss keypair must succeed");
        let signature = scheme
            .sign(&message, &mut secret_key)
            .expect("xmss sign must succeed");
        std::hint::black_box(signature);
    });
}

#[divan::bench(args = [32_usize, 1024_usize])]
fn verify(bencher: Bencher, message_size: usize) {
    let scheme = XmssScheme::new(XmssParamSet::XmssSha2_10_256);
    let message = vec![0x3C; message_size];
    let (public_key, mut secret_key) =
        scheme.keypair().expect("xmss keypair must succeed");
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
