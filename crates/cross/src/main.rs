use cross::{memory, TrackingAllocator, ALLOCATION_TRACKER, CROSS};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    pq_bench::run_standard_signed_message_scheme_main!(
        scheme = CROSS,
        algorithm = "CROSS",
        param_set = CROSS.algorithm_name(),
        heading_algorithm = "CROSS",
        heading_param_set = CROSS.algorithm_name(),
        summary_algorithm = CROSS.algorithm_name(),
        backend = None,
        reset_peak = memory::reset_peak,
        peak_bytes = memory::peak_bytes
    );
}
