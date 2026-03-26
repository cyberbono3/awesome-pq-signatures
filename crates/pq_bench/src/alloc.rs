use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct AllocationTracker {
    allocated: AtomicUsize,
    peak_allocated: AtomicUsize,
    baseline: AtomicUsize,
    total_allocated: AtomicUsize,
    tracking_enabled: AtomicBool,
}

impl AllocationTracker {
    pub const fn new() -> Self {
        Self {
            allocated: AtomicUsize::new(0),
            peak_allocated: AtomicUsize::new(0),
            baseline: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
            tracking_enabled: AtomicBool::new(false),
        }
    }

    pub fn reset_peak(&self) {
        let current = self.allocated.load(Ordering::SeqCst);
        self.baseline.store(current, Ordering::SeqCst);
        self.peak_allocated.store(0, Ordering::SeqCst);
        self.total_allocated.store(0, Ordering::SeqCst);
        self.tracking_enabled.store(true, Ordering::SeqCst);
    }

    pub fn stop_tracking(&self) {
        self.tracking_enabled.store(false, Ordering::SeqCst);
    }

    pub fn peak_bytes(&self) -> usize {
        self.peak_allocated.load(Ordering::SeqCst)
    }

    pub fn total_allocated_bytes(&self) -> usize {
        self.total_allocated.load(Ordering::SeqCst)
    }

    pub fn current_bytes(&self) -> usize {
        self.allocated.load(Ordering::SeqCst)
    }

    fn track_alloc(&self, size: usize) {
        let current = self.allocated.fetch_add(size, Ordering::SeqCst) + size;

        if self.tracking_enabled.load(Ordering::SeqCst) {
            self.total_allocated.fetch_add(size, Ordering::SeqCst);
        }

        let baseline = self.baseline.load(Ordering::SeqCst);
        let relative_current = current.saturating_sub(baseline);
        let mut peak = self.peak_allocated.load(Ordering::SeqCst);

        while relative_current > peak {
            match self.peak_allocated.compare_exchange_weak(
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

    fn track_dealloc(&self, size: usize) {
        self.allocated.fetch_sub(size, Ordering::SeqCst);
    }
}

pub struct AllocationTrackingAllocator<A: GlobalAlloc + Sync + 'static> {
    inner: &'static A,
    tracker: &'static AllocationTracker,
}

impl<A: GlobalAlloc + Sync + 'static> AllocationTrackingAllocator<A> {
    pub const fn new(
        inner: &'static A,
        tracker: &'static AllocationTracker,
    ) -> Self {
        Self { inner, tracker }
    }
}

unsafe impl<A: GlobalAlloc + Sync + 'static> GlobalAlloc
    for AllocationTrackingAllocator<A>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            self.tracker.track_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        self.tracker.track_dealloc(layout.size());
    }
}
