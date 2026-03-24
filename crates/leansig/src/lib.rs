use leansig::serialization::Serializable;
use leansig::signature::SignatureScheme;
use leansig::signature::SignatureSchemeSecretKey;
use leansig::MESSAGE_LENGTH;

pub use pq_bench::{measure_time, BENCH_MESSAGE};

pub const BENCHMARK_EPOCH: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeansigBenchmarkRun {
    pub keygen_duration: std::time::Duration,
    pub sign_duration: std::time::Duration,
    pub verify_duration: std::time::Duration,
    pub verified: bool,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub signature_bytes: usize,
}

/// Advance secret-key preparation until `epoch` is inside the prepared
/// interval.
pub fn prepare_sk_for_epoch<SK: SignatureSchemeSecretKey>(
    sk: &mut SK,
    epoch: u32,
) {
    let mut iterations = 0u32;
    while !sk.get_prepared_interval().contains(&(epoch as u64))
        && iterations < epoch
    {
        sk.advance_preparation();
        iterations += 1;
    }
    assert!(
        sk.get_prepared_interval().contains(&(epoch as u64)),
        "Failed to advance key preparation to epoch {epoch}"
    );
}

pub fn benchmark_message_array<const N: usize>(message: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let copy_len = message.len().min(N);
    output[..copy_len].copy_from_slice(&message[..copy_len]);
    output
}

pub fn benchmark_once<S: SignatureScheme>(
    message: &[u8],
) -> Result<LeansigBenchmarkRun, String> {
    let mut rng = rand::rng();
    let activation_epoch: usize = 0;
    let num_active_epochs = S::LIFETIME as usize;
    let ((pk, mut sk), keygen_duration) = measure_time(|| {
        S::key_gen(&mut rng, activation_epoch, num_active_epochs)
    });
    prepare_sk_for_epoch(&mut sk, BENCHMARK_EPOCH);
    let message = benchmark_message_array::<MESSAGE_LENGTH>(message);
    let (sig_result, sign_duration) =
        measure_time(|| S::sign(&sk, BENCHMARK_EPOCH, &message));
    let sig =
        sig_result.map_err(|err| format!("LeanSig signing failed: {err:?}"))?;
    let (verified, verify_duration) =
        measure_time(|| S::verify(&pk, BENCHMARK_EPOCH, &message, &sig));

    Ok(LeansigBenchmarkRun {
        keygen_duration,
        sign_duration,
        verify_duration,
        verified,
        public_key_bytes: pk.to_bytes().len(),
        secret_key_bytes: sk.to_bytes().len(),
        signature_bytes: sig.to_bytes().len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_message_array_copies_and_zero_pads() {
        let message = benchmark_message_array::<8>(b"abc");
        assert_eq!(&message[..3], b"abc");
        assert_eq!(&message[3..], &[0, 0, 0, 0, 0]);
    }
}
