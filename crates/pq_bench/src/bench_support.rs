use crate::bench_message;

pub fn signed_fixture<K, S>(
    message_size: usize,
    keygen: impl FnOnce() -> K,
    sign: impl FnOnce(&K, &[u8]) -> S,
) -> (K, Vec<u8>, S) {
    let keypair = keygen();
    let message = bench_message(message_size);
    let signature = sign(&keypair, &message);
    (keypair, message, signature)
}

pub fn print_signed_message_sizes<K, S>(
    algorithm_name: &str,
    message_sizes: &[usize],
    keygen: impl FnOnce() -> K,
    public_key_size: impl Fn(&K) -> usize,
    secret_key_size: impl Fn(&K) -> usize,
    sign: impl Fn(&K, &[u8]) -> S,
    signature_size: impl Fn(&S) -> usize,
) {
    let keypair = keygen();
    println!("{algorithm_name} sizes:");
    println!("  Public key: {} bytes", public_key_size(&keypair));
    println!("  Secret key: {} bytes", secret_key_size(&keypair));

    for &message_size in message_sizes {
        let message = bench_message(message_size);
        let signature = sign(&keypair, &message);
        println!(
            "  Signature (message {} bytes): {} bytes",
            message_size,
            signature_size(&signature)
        );
    }
}

pub fn print_signed_message_memory_usage<K, S>(
    algorithm_name: &str,
    message_sizes: &[usize],
    keygen: impl FnOnce() -> K,
    sign: impl Fn(&K, &[u8]) -> S,
    verify: impl Fn(&K, &[u8], &S),
    reset_peak: impl Fn(),
    peak_bytes: impl Fn() -> usize,
) {
    let keypair = keygen();
    println!("{algorithm_name} peak heap usage:");

    for &message_size in message_sizes {
        let message = bench_message(message_size);

        reset_peak();
        let signature = sign(&keypair, &message);
        let sign_peak = peak_bytes();

        reset_peak();
        verify(&keypair, &message, &signature);
        let verify_peak = peak_bytes();

        println!(
            "  Message {message_size} bytes: sign={sign_peak} bytes, verify={verify_peak} bytes"
        );
    }
}
