use sha2::{Digest, Sha256};
use std::env;

const HASH_SIZE: usize = 32;
const BITS: usize = 256;

#[derive(Clone)]
struct Keypair {
    sk: Vec<[u8; HASH_SIZE]>,
    pk: Vec<[u8; HASH_SIZE]>,
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let v = self.next_u64().to_le_bytes();
            let take = (out.len() - i).min(v.len());
            out[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
    }
}

fn env_bool(key: &str) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => false,
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn seed_from_str(s: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn init_rng() -> XorShift64 {
    let deterministic = env_bool("DETERMINISTIC_RNG");
    let seed = env::var("RNG_SEED").ok();
    if let Some(s) = seed {
        return XorShift64::new(seed_from_str(&s));
    }
    if deterministic {
        return XorShift64::new(0x6c62272e07bb0142);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id() as u64;
    XorShift64::new(now.as_nanos() as u64 ^ (pid << 32))
}

fn hash_bytes(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest[..HASH_SIZE]);
    out
}

fn canary_buffer(len: usize, rng: &mut XorShift64) -> Vec<u8> {
    let mut buf = vec![0u8; len + 16];
    let mut canary = [0u8; 8];
    rng.fill_bytes(&mut canary);
    buf[..8].copy_from_slice(&canary);
    buf[len + 8..].copy_from_slice(&canary);
    buf
}

fn check_canary(buf: &[u8], len: usize) -> bool {
    if buf.len() < len + 16 {
        return false;
    }
    let head = &buf[..8];
    let tail = &buf[len + 8..len + 16];
    head == tail
}

fn keygen(rng: &mut XorShift64, canary_check: bool) -> Keypair {
    let mut sk = Vec::with_capacity(BITS * 2);
    let mut pk = Vec::with_capacity(BITS * 2);

    for _ in 0..(BITS * 2) {
        let mut secret = [0u8; HASH_SIZE];
        if canary_check {
            let mut buf = canary_buffer(HASH_SIZE, rng);
            rng.fill_bytes(&mut buf[8..8 + HASH_SIZE]);
            if !check_canary(&buf, HASH_SIZE) {
                eprintln!("canary check failed during keygen");
                std::process::exit(1);
            }
            secret.copy_from_slice(&buf[8..8 + HASH_SIZE]);
        } else {
            rng.fill_bytes(&mut secret);
        }
        sk.push(secret);
        pk.push(hash_bytes(&secret));
    }

    Keypair { sk, pk }
}

fn sign(digest: &[u8; HASH_SIZE], kp: &Keypair) -> Vec<[u8; HASH_SIZE]> {
    let mut sig = Vec::with_capacity(BITS);
    for i in 0..BITS {
        let byte = digest[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        let idx = (i * 2) + (bit as usize);
        sig.push(kp.sk[idx]);
    }
    sig
}

fn verify(digest: &[u8; HASH_SIZE], sig: &[[u8; HASH_SIZE]], kp: &Keypair) -> bool {
    for i in 0..BITS {
        let byte = digest[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        let idx = (i * 2) + (bit as usize);
        if hash_bytes(&sig[i]) != kp.pk[idx] {
            return false;
        }
    }
    true
}

fn main() {
    let iterations = env_usize("ITERATIONS", 1);
    let msg_size = env_usize("MSG_SIZE", 32);
    let operation = env::var("OPERATION").unwrap_or_else(|_| "sign".to_string());
    let prehash = env_bool("PREHASH");
    let canary_check = env_bool("CANARY_CHECK");
    let stack_check = env_bool("STACK_CHECK");
    let hash_only = env_bool("HASH_ONLY");
    let _code_size = env_bool("CODE_SIZE");

    if stack_check {
        let mut scratch = [0u8; 1024];
        for (i, b) in scratch.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        std::hint::black_box(&scratch);
    }

    let mut rng = init_rng();
    let mut message = vec![0u8; msg_size];
    rng.fill_bytes(&mut message);

    if hash_only {
        for _ in 0..iterations {
            let h = hash_bytes(&message);
            std::hint::black_box(h);
        }
        return;
    }

    let kp = keygen(&mut rng, canary_check);

    let digest = if prehash && msg_size == HASH_SIZE {
        let mut d = [0u8; HASH_SIZE];
        d.copy_from_slice(&message[..HASH_SIZE]);
        d
    } else {
        hash_bytes(&message)
    };

    match operation.as_str() {
        "keygen" => {
            for _ in 0..iterations {
                let kp = keygen(&mut rng, canary_check);
                std::hint::black_box(&kp);
            }
        }
        "sign" => {
            for _ in 0..iterations {
                let sig = sign(&digest, &kp);
                std::hint::black_box(&sig);
            }
        }
        "verify" => {
            let sig = sign(&digest, &kp);
            for _ in 0..iterations {
                let ok = verify(&digest, &sig, &kp);
                std::hint::black_box(ok);
            }
        }
        other => {
            eprintln!("unknown OPERATION: {other}");
            std::process::exit(1);
        }
    }
}
