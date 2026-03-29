use std::collections::HashMap;
use std::path::PathBuf;

use pq_bench::measure_time;

use crate::types::{BenchRun, SizeMetrics};

pub struct RunnerContext {
    pub message_size: usize,
    pub binary_executables: HashMap<&'static str, PathBuf>,
}

pub fn measure_benchmark_flow<K, S>(
    keygen: impl FnOnce() -> K,
    sign: impl FnOnce(&mut K) -> S,
    verify: impl FnOnce(&K, &S),
    sizes: impl FnOnce(&K, &S) -> SizeMetrics,
) -> BenchRun {
    let (mut key_material, keygen_duration) = measure_time(keygen);
    let (signature, sign_duration) = measure_time(|| sign(&mut key_material));
    let (_, verify_duration) =
        measure_time(|| verify(&key_material, &signature));
    BenchRun::from_durations(
        keygen_duration,
        sign_duration,
        verify_duration,
        sizes(&key_material, &signature),
    )
}
