use cross::{
    memory, CrossKeyPair, CrossSignature, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE_SIZES, CROSS,
};
pq_bench::install_divan_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

pq_bench::declare_signed_message_divan_bench!(
    scheme = CROSS,
    keypair = CrossKeyPair,
    signature = CrossSignature,
    message_sizes = BENCH_MESSAGE_SIZES,
    reset_peak = memory::reset_peak,
    peak_bytes = memory::peak_bytes
);
