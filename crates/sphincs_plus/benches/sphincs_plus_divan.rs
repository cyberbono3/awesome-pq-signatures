use sphincs_plus::{
    memory, SphincsPlusKeyPair, SphincsPlusSignature, TrackingAllocator,
    ALLOCATION_TRACKER, BENCH_MESSAGE_SIZES, SPHINCS_PLUS_SHAKE_128F_SIMPLE,
};
pq_bench::install_divan_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

pq_bench::declare_signed_message_divan_bench!(
    scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE,
    keypair = SphincsPlusKeyPair,
    signature = SphincsPlusSignature,
    message_sizes = BENCH_MESSAGE_SIZES,
    reset_peak = memory::reset_peak,
    peak_bytes = memory::peak_bytes
);
