use sqisign::{memory, TrackingAllocator, ALLOCATION_TRACKER, SQISIGN};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    pq_bench::run_standard_signed_message_scheme_main!(
        scheme = SQISIGN,
        algorithm = "SQISign",
        param_set = "SQISign-lvl1",
        heading_algorithm = "SQISign",
        heading_param_set = SQISIGN.algorithm_name(),
        summary_algorithm = SQISIGN.algorithm_name(),
        backend = None,
        reset_peak = memory::reset_peak,
        peak_bytes = memory::peak_bytes
    );
}
