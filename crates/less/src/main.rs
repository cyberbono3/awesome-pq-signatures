use less::{memory, TrackingAllocator, ALLOCATION_TRACKER, LESS};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    pq_bench::run_standard_signed_message_scheme_main!(
        scheme = LESS,
        algorithm = "LESS",
        param_set = LESS.algorithm_name(),
        heading_algorithm = "LESS",
        heading_param_set = LESS.algorithm_name(),
        summary_algorithm = LESS.algorithm_name(),
        backend = None,
        reset_peak = memory::reset_peak,
        peak_bytes = memory::peak_bytes
    );
}
