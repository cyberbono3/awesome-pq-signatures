use ml_dsa::{KeyGen, MlDsa65, B32};
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
    println!("=== Dilithium (ML-DSA-65) Benchmark ===\n");

    // Message to sign
    let message =
        b"This is a test message for Dilithium signature scheme benchmarking";
    let context: &[u8] = &[];
    let seed: B32 = [7u8; 32].into();

    // 1. Key Generation Timing
    println!("--- Key Generation ---");

    let start = Instant::now();
    let kp = MlDsa65::key_gen_internal(&seed);
    let keygen_duration = start.elapsed();

    println!("Time to generate keys: {:?}", keygen_duration);
    println!("Time to generate keys (ns): {}", keygen_duration.as_nanos());

    // 2. Signing Timing
    println!("\n--- Signing ---");
    reset_memory_tracking();

    let start = Instant::now();
    let signed_msg = kp
        .signing_key()
        .sign_deterministic(message, context)
        .expect("signing should succeed");
    let sign_duration = start.elapsed();

    println!("Time to sign: {:?}", sign_duration);
    println!("Time to sign (ns): {}", sign_duration.as_nanos());

    let sign_peak_mem = get_peak_memory();
    println!("Peak memory during signing: {} bytes", sign_peak_mem);

    // 3. Verification Timing
    println!("\n--- Verification ---");
    reset_memory_tracking();

    let start = Instant::now();
    let verified =
        kp.verifying_key()
            .verify_with_context(message, context, &signed_msg);
    let verify_duration = start.elapsed();

    println!("Time to verify: {:?}", verify_duration);
    println!("Time to verify (ns): {}", verify_duration.as_nanos());

    let verify_peak_mem = get_peak_memory();
    println!("Peak memory during verification: {} bytes", verify_peak_mem);

    if verified {
        println!("Signature verification: SUCCESS");
    } else {
        println!("Signature verification: FAILED");
    }

    let pk_bytes = kp.verifying_key().encode();
    let sk_bytes = kp.signing_key().encode();
    let sig_bytes = signed_msg.encode();

    // 4. Size Measurements
    println!("\n--- Size Measurements ---");
    println!("Public key size: {} bytes", pk_bytes.len());
    println!("Secret key size: {} bytes", sk_bytes.len());
    println!("Signature size: {} bytes", sig_bytes.len());
    println!(
        "Signed message size: {} bytes",
        message.len() + sig_bytes.len()
    );

    // Summary
    println!("\n=== Summary ===");
    println!("Algorithm: ML-DSA-65");
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
    println!("  Public Key:  {} bytes", pk_bytes.len());
    println!("  Secret Key:  {} bytes", sk_bytes.len());
    println!("  Signature:   {} bytes", sig_bytes.len());
    println!("\nMemory Usage (heap allocations):");
    println!("  Signing:      {} bytes", sign_peak_mem);
    println!("  Verification: {} bytes", verify_peak_mem);
}
