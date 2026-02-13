use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if !ret.is_null() {
            let size = layout.size();
            let current = ALLOCATED.fetch_add(size, Ordering::SeqCst) + size;

            // Update peak relative to baseline
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
                    Err(x) => peak = x,
                }
            }
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

fn reset_memory_tracking() {
    let current = ALLOCATED.load(Ordering::SeqCst);
    BASELINE.store(current, Ordering::SeqCst);
    PEAK_ALLOCATED.store(0, Ordering::SeqCst);
}

fn get_peak_memory() -> usize {
    PEAK_ALLOCATED.load(Ordering::SeqCst)
}

fn main() {
    println!("=== Falcon-512 Benchmark ===\n");

    // Message to sign
    let message = b"This is a test message for Falcon signature scheme benchmarking";

    // 1. Key Generation Timing
    println!("--- Key Generation ---");

    let start = Instant::now();
    let (pk, sk) = falcon512::keypair();
    let keygen_duration = start.elapsed();

    println!("Time to generate keys: {:?}", keygen_duration);
    println!("Time to generate keys (ns): {}", keygen_duration.as_nanos());

    // 2. Signing Timing
    println!("\n--- Signing ---");
    reset_memory_tracking();

    let start = Instant::now();
    let signed_msg = falcon512::sign(message, &sk);
    let sign_duration = start.elapsed();

    println!("Time to sign: {:?}", sign_duration);
    println!("Time to sign (ns): {}", sign_duration.as_nanos());

    let sign_peak_mem = get_peak_memory();
    println!("Peak memory during signing: {} bytes", sign_peak_mem);

    // 3. Verification Timing
    println!("\n--- Verification ---");
    reset_memory_tracking();

    let start = Instant::now();
    let verified_msg = falcon512::open(&signed_msg, &pk);
    let verify_duration = start.elapsed();

    println!("Time to verify: {:?}", verify_duration);
    println!("Time to verify (ns): {}", verify_duration.as_nanos());

    let verify_peak_mem = get_peak_memory();
    println!("Peak memory during verification: {} bytes", verify_peak_mem);

    match verified_msg {
        Ok(msg) => {
            if msg == message {
                println!("Signature verification: SUCCESS");
            } else {
                println!("Signature verification: FAILED (message mismatch)");
            }
        }
        Err(_) => println!("Signature verification: FAILED"),
    }

    // 4. Size Measurements
    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", pk.as_bytes().len());
    println!("Secret key size: {} bytes", sk.as_bytes().len());
    println!(
        "Signature size: {} bytes",
        signed_msg.as_bytes().len() - message.len()
    );
    println!("Signed message size: {} bytes", signed_msg.as_bytes().len());

    // Summary
    println!("\n=== Summary ===");
    println!("Algorithm: Falcon-512");
    println!("\nTiming:");
    println!(
        "  Key Generation: {:?} ({} ns)",
        keygen_duration,
        keygen_duration.as_nanos()
    );
    println!(
        "  Signing:        {:?} ({} ns)",
        sign_duration,
        sign_duration.as_nanos()
    );
    println!(
        "  Verification:   {:?} ({} ns)",
        verify_duration,
        verify_duration.as_nanos()
    );
    println!("\nSizes:");
    println!("  Public Key:  {} bytes", pk.as_bytes().len());
    println!("  Secret Key:  {} bytes", sk.as_bytes().len());
    println!(
        "  Signature:   {} bytes",
        signed_msg.as_bytes().len() - message.len()
    );
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {} bytes", sign_peak_mem);
    println!("  Verification: {} bytes", verify_peak_mem);
}
