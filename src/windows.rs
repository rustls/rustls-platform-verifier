//! Utilities to deal with weird aspects of interfacing with Windows through `winapi`.
#![allow(clippy::as_conversions)]

use std::ptr::NonNull;

/// A trait to represent an object that can be safely created with all zero values
/// and have a size assigned to it.
///
/// # Safety
///
/// This has the same safety requirements as [std::mem::zeroed].
pub(crate) unsafe trait ZeroedWithSize {
    /// Returns a zeroed structure with its structure size (`cbsize`) field set to the correct value.
    fn zeroed_with_size() -> Self;
}

/// Returns `p` as a `*const c_void`.
///
/// The conversion is done in the most type-safe way possible.
pub(crate) fn c_void_from_ref<T>(p: &T) -> *const winapi::ctypes::c_void {
    let p: *const T = p;
    p as *const winapi::ctypes::c_void
}

/// Returns `p` as a `*mut c_void`.
///
/// The conversion is done in the most type-safe way possible.
pub(crate) fn c_void_from_ref_mut<T>(p: &mut T) -> *mut winapi::ctypes::c_void {
    let p: *mut T = p;
    p as *mut winapi::ctypes::c_void
}

/// Returns `p` as a `NonNull<T>`, erasing its `const`-ness.
///
/// The conversion is done in the most type-safe way possible.
pub(crate) fn nonnull_from_const_ptr<T>(p: *const T) -> Option<NonNull<T>> {
    NonNull::new(p as *mut T)
}
