use sphincs_plus::{
    memory, TrackingAllocator, ALLOCATION_TRACKER,
    SPHINCS_PLUS_SHAKE_128F_SIMPLE,
};
pq_bench::install_system_tracking_allocator!(
    TrackingAllocator,
    ALLOCATION_TRACKER
);

fn main() {
    pq_bench::run_standard_signed_message_scheme_main!(
        scheme = SPHINCS_PLUS_SHAKE_128F_SIMPLE,
        algorithm = SPHINCS_PLUS_SHAKE_128F_SIMPLE.algorithm_name(),
        param_set = SPHINCS_PLUS_SHAKE_128F_SIMPLE.algorithm_name(),
        heading_algorithm = SPHINCS_PLUS_SHAKE_128F_SIMPLE.algorithm_name(),
        heading_param_set = SPHINCS_PLUS_SHAKE_128F_SIMPLE.algorithm_name(),
        summary_algorithm = SPHINCS_PLUS_SHAKE_128F_SIMPLE.algorithm_name(),
        backend = None,
        reset_peak = memory::reset_peak,
        peak_bytes = memory::peak_bytes
    );
}
