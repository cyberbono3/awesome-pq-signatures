mod generated {
    include!(concat!(env!("OUT_DIR"), "/bench_message.rs"));
}

pub use generated::BENCH_MESSAGE;

pub const BENCH_MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];
pub const BENCH_MESSAGE_BYTE: u8 = 0x42;
pub const BENCHMARK_SEED_U64: u64 = 0x7A5B_91C3_E4D2_F607;

pub fn bench_message(size: usize) -> Vec<u8> {
    vec![BENCH_MESSAGE_BYTE; size]
}

pub fn benchmark_message(size: usize) -> Vec<u8> {
    if size == BENCH_MESSAGE.len() {
        BENCH_MESSAGE.to_vec()
    } else {
        bench_message(size)
    }
}

pub fn benchmark_seed_u64() -> u64 {
    BENCHMARK_SEED_U64
}

pub fn benchmark_seed_array<const N: usize>() -> [u8; N] {
    expand_seed_u64(BENCHMARK_SEED_U64)
}

pub fn expand_seed_u64<const N: usize>(seed_value: u64) -> [u8; N] {
    let mut state = seed_value;
    let mut output = [0u8; N];
    let mut offset = 0;

    while offset < N {
        state = splitmix64(state);
        let chunk = state.to_le_bytes();
        let take = (N - offset).min(chunk.len());
        output[offset..offset + take].copy_from_slice(&chunk[..take]);
        offset += take;
    }

    output
}

pub fn signed_message_size(message_len: usize, signature_len: usize) -> usize {
    message_len.saturating_add(signature_len)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
