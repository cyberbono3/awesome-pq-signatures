use std::sync::Mutex;

pub fn with_ffi_lock<T, E>(
    lock: &Mutex<()>,
    poison_error: impl Fn() -> E,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let _guard = lock.lock().map_err(|_| poison_error())?;
    operation()
}
