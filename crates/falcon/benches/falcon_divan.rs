use divan::{black_box, AllocProfiler, Bencher};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator;

struct TrackingAllocator;

static DIVAN_ALLOC: AllocProfiler = AllocProfiler::system();
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);

const MESSAGE_SIZES: [usize; 4] = [32, 256, 1024, 4096];

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { DIVAN_ALLOC.alloc(layout) };
        if !ptr.is_null() {
            let size = layout.size();
            let current = ALLOCATED.fetch_add(size, Ordering::SeqCst) + size;
            let baseline = BASELINE.load(Ordering::SeqCst);
            let relative_current = current.saturating_sub(baseline);
            let mut peak = PEAK_ALLOCATED.load(Ordering::SeqCst);

            while relative_current > peak {
                match PEAK_ALLOCATED.compare_exchange_weak(
                    peak,
                    relative_current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(observed) => peak = observed,
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { DIVAN_ALLOC.dealloc(ptr, layout) };
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

fn reset_memory_tracking() {
    let current = ALLOCATED.load(Ordering::SeqCst);
    BASELINE.store(current, Ordering::SeqCst);
    PEAK_ALLOCATED.store(0, Ordering::SeqCst);
}

fn peak_memory_bytes() -> usize {
    PEAK_ALLOCATED.load(Ordering::SeqCst)
}

#[divan::bench]
fn keygen(bencher: Bencher) {
    bencher.bench(|| {
        black_box(falcon512::keypair());
    });
}

#[divan::bench(args = MESSAGE_SIZES)]
fn sign(bencher: Bencher, message_size: usize) {
    let message = vec![0x42; message_size];
    let (_, secret_key) = falcon512::keypair();

    bencher.bench(|| {
        black_box(falcon512::sign(
            black_box(message.as_slice()),
            black_box(&secret_key),
        ));
    });
}

#[divan::bench(args = MESSAGE_SIZES)]
fn verify(bencher: Bencher, message_size: usize) {
    let message = vec![0x42; message_size];
    let (public_key, secret_key) = falcon512::keypair();
    let signed_message = falcon512::sign(&message, &secret_key);

    bencher.bench(|| {
        let opened = falcon512::open(black_box(&signed_message), black_box(&public_key))
            .expect("falcon verify benchmark input should always be valid");
        black_box(opened);
    });
}

fn print_sizes() {
    let (public_key, secret_key) = falcon512::keypair();
    println!("Falcon-512 sizes:");
    println!("  Public key: {} bytes", public_key.as_bytes().len());
    println!("  Secret key: {} bytes", secret_key.as_bytes().len());

    for message_size in MESSAGE_SIZES {
        let message = vec![0x42; message_size];
        let signed_message = falcon512::sign(&message, &secret_key);
        let signature_size = signed_message.as_bytes().len().saturating_sub(message.len());
        println!("  Signature (message {} bytes): {} bytes", message_size, signature_size);
    }
}

fn print_memory_usage() {
    println!("Falcon-512 peak heap usage:");
    let (public_key, secret_key) = falcon512::keypair();

    for message_size in MESSAGE_SIZES {
        let message = vec![0x42; message_size];

        reset_memory_tracking();
        let signed_message = falcon512::sign(&message, &secret_key);
        let sign_peak = peak_memory_bytes();

        reset_memory_tracking();
        let _opened = falcon512::open(&signed_message, &public_key)
            .expect("benchmark setup should verify the signed message");
        let verify_peak = peak_memory_bytes();

        println!(
            "  Message {} bytes: sign={} bytes, verify={} bytes",
            message_size, sign_peak, verify_peak
        );
    }
}

fn main() {
    print_sizes();
    print_memory_usage();
    divan::main();
}
