use falcon::{
    memory, FalconKeyPair, FalconSignature, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE_SIZES, FALCON512,
};
pq_bench::install_divan_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

pq_bench::declare_signed_message_divan_bench!(
    scheme = FALCON512,
    keypair = FalconKeyPair,
    signature = FalconSignature,
    message_sizes = BENCH_MESSAGE_SIZES,
    reset_peak = memory::reset_peak,
    peak_bytes = memory::peak_bytes
);
