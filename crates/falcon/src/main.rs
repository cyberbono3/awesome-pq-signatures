use falcon::{memory, TrackingAllocator, ALLOCATION_TRACKER, FALCON512};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    pq_bench::run_standard_signed_message_scheme_main!(
        scheme = FALCON512,
        algorithm = FALCON512.algorithm_name(),
        param_set = FALCON512.algorithm_name(),
        heading_algorithm = FALCON512.algorithm_name(),
        heading_param_set = FALCON512.algorithm_name(),
        summary_algorithm = FALCON512.algorithm_name(),
        backend = None,
        reset_peak = memory::reset_peak,
        peak_bytes = memory::peak_bytes
    );
}
