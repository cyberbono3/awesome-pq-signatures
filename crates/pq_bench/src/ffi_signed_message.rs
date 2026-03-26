use std::ffi::{c_int, c_uchar, c_ulonglong};
use std::sync::Mutex;

use crate::signed_message_size;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FfiSignedMessageDimensions {
    pub public_key: usize,
    pub secret_key: usize,
    pub signature: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicRngProfile<const N: usize> {
    pub seed: [u8; N],
    pub domain_separator: u16,
}

pub fn with_ffi_lock<T, E>(
    lock: &Mutex<()>,
    poison_error: impl Fn() -> E,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let _guard = lock.lock().map_err(|_| poison_error())?;
    operation()
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

pub fn ffi_keypair<K, E>(
    dimensions: FfiSignedMessageDimensions,
    call_keypair: impl FnOnce(*mut c_uchar, *mut c_uchar) -> c_int,
    build_keypair: impl FnOnce(Vec<u8>, Vec<u8>) -> K,
    keygen_error: impl FnOnce(c_int) -> E,
) -> Result<K, E> {
    let mut public_key = vec![0_u8; dimensions.public_key];
    let mut secret_key = vec![0_u8; dimensions.secret_key];
    let rc = call_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr());

    if rc == 0 {
        Ok(build_keypair(public_key, secret_key))
    } else {
        Err(keygen_error(rc))
    }
}

pub fn ffi_deterministic_keypair<K, E, const N: usize>(
    lock: &Mutex<()>,
    profile: DeterministicRngProfile<N>,
    init_rng: impl FnOnce(&DeterministicRngProfile<N>),
    dimensions: FfiSignedMessageDimensions,
    call_keypair: impl FnOnce(*mut c_uchar, *mut c_uchar) -> c_int,
    build_keypair: impl FnOnce(Vec<u8>, Vec<u8>) -> K,
    poison_error: impl Fn() -> E,
    keygen_error: impl FnOnce(c_int) -> E,
) -> Result<K, E> {
    with_deterministic_rng(
        lock,
        poison_error,
        || init_rng(&profile),
        || ffi_keypair(dimensions, call_keypair, build_keypair, keygen_error),
    )
}

pub fn ffi_sign<S, E>(
    dimensions: FfiSignedMessageDimensions,
    message: &[u8],
    secret_key: &[u8],
    call_sign: impl FnOnce(
        *mut c_uchar,
        *mut c_ulonglong,
        *const c_uchar,
        c_ulonglong,
        *const c_uchar,
    ) -> c_int,
    build_signature: impl FnOnce(Vec<u8>) -> S,
    sign_error: impl FnOnce(c_int) -> E,
    length_overflow: impl Fn() -> E,
    invalid_signed_message: impl Fn() -> E,
) -> Result<S, E> {
    let message_len = ulonglong_len(message.len(), &length_overflow)?;
    let mut signed_message =
        vec![0_u8; signed_message_size(message.len(), dimensions.signature)];
    let mut signed_message_len = 0_u64;

    let rc = call_sign(
        signed_message.as_mut_ptr(),
        &raw mut signed_message_len,
        message.as_ptr(),
        message_len,
        secret_key.as_ptr(),
    );

    if rc != 0 {
        return Err(sign_error(rc));
    }

    let signed_message_len = usize_len(signed_message_len, &length_overflow)?;
    extract_signature(
        message.len(),
        &signed_message,
        signed_message_len,
        build_signature,
        invalid_signed_message,
    )
}

pub fn ffi_deterministic_sign<S, E, const N: usize>(
    lock: &Mutex<()>,
    profile: DeterministicRngProfile<N>,
    init_rng: impl FnOnce(&DeterministicRngProfile<N>),
    dimensions: FfiSignedMessageDimensions,
    message: &[u8],
    secret_key: &[u8],
    call_sign: impl FnOnce(
        *mut c_uchar,
        *mut c_ulonglong,
        *const c_uchar,
        c_ulonglong,
        *const c_uchar,
    ) -> c_int,
    build_signature: impl FnOnce(Vec<u8>) -> S,
    poison_error: impl Fn() -> E,
    sign_error: impl FnOnce(c_int) -> E,
    length_overflow: impl Fn() -> E,
    invalid_signed_message: impl Fn() -> E,
) -> Result<S, E> {
    with_deterministic_rng(
        lock,
        poison_error,
        || init_rng(&profile),
        || {
            ffi_sign(
                dimensions,
                message,
                secret_key,
                call_sign,
                build_signature,
                sign_error,
                length_overflow,
                invalid_signed_message,
            )
        },
    )
}

pub fn ffi_verify<E>(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    call_open: impl FnOnce(
        *mut c_uchar,
        *mut c_ulonglong,
        *const c_uchar,
        c_ulonglong,
        *const c_uchar,
    ) -> c_int,
    verify_error: impl FnOnce(c_int) -> E,
    length_overflow: impl Fn() -> E,
) -> Result<bool, E> {
    let signed_message = combine_signed_message(message, signature);
    let signed_message_len =
        ulonglong_len(signed_message.len(), &length_overflow)?;
    let mut opened_message = vec![0_u8; message.len()];
    let mut opened_message_len = 0_u64;

    let rc = call_open(
        opened_message.as_mut_ptr(),
        &raw mut opened_message_len,
        signed_message.as_ptr(),
        signed_message_len,
        public_key.as_ptr(),
    );

    match rc {
        0 => {
            let opened_message_len =
                usize_len(opened_message_len, &length_overflow)?;
            Ok(matches_opened_message(
                message,
                &opened_message,
                opened_message_len,
            ))
        }
        -1 => Ok(false),
        _ => Err(verify_error(rc)),
    }
}

pub fn ffi_locked_verify<E>(
    lock: &Mutex<()>,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    call_open: impl FnOnce(
        *mut c_uchar,
        *mut c_ulonglong,
        *const c_uchar,
        c_ulonglong,
        *const c_uchar,
    ) -> c_int,
    poison_error: impl Fn() -> E,
    verify_error: impl FnOnce(c_int) -> E,
    length_overflow: impl Fn() -> E,
) -> Result<bool, E> {
    with_ffi_lock(lock, poison_error, || {
        ffi_verify(
            message,
            signature,
            public_key,
            call_open,
            verify_error,
            length_overflow,
        )
    })
}

fn ulonglong_len<E>(
    value: usize,
    length_overflow: &impl Fn() -> E,
) -> Result<c_ulonglong, E> {
    c_ulonglong::try_from(value).map_err(|_| length_overflow())
}

fn usize_len<E>(
    value: c_ulonglong,
    length_overflow: &impl Fn() -> E,
) -> Result<usize, E> {
    usize::try_from(value).map_err(|_| length_overflow())
}

fn extract_signature<S, E>(
    message_len: usize,
    signed_message: &[u8],
    signed_message_len: usize,
    build_signature: impl FnOnce(Vec<u8>) -> S,
    invalid_signed_message: impl Fn() -> E,
) -> Result<S, E> {
    signed_message
        .get(message_len..signed_message_len)
        .map(|bytes| build_signature(bytes.to_vec()))
        .ok_or_else(invalid_signed_message)
}

fn combine_signed_message(message: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut signed_message =
        Vec::with_capacity(signed_message_size(message.len(), signature.len()));
    signed_message.extend_from_slice(message);
    signed_message.extend_from_slice(signature);
    signed_message
}

fn matches_opened_message(
    expected_message: &[u8],
    opened_message: &[u8],
    opened_message_len: usize,
) -> bool {
    opened_message_len == expected_message.len()
        && opened_message
            .get(..opened_message_len)
            .is_some_and(|message| message == expected_message)
}
