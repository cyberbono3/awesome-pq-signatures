use std::sync::Mutex;

use super::locking::with_ffi_lock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicRngProfile<const N: usize> {
    pub seed: [u8; N],
    pub domain_separator: u16,
}

pub fn with_deterministic_rng<T, E>(
    lock: &Mutex<()>,
    poison_error: impl Fn() -> E,
    init_rng: impl FnOnce(),
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    with_ffi_lock(lock, poison_error, || {
        init_rng();
        operation()
    })
}
