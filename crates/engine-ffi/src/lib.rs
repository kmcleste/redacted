/*!
C ABI for in-process gateway embedding — the zero-hop, zero-alloc path (D13).

Safety contract:
- All `*const c_char` inputs must be valid UTF-8, null-terminated C strings.
- All `*mut u8` outputs are caller-allocated buffers; `out_len` is in/out.
- `engine_mask` and `engine_rehydrate` write into the provided buffer and
  return the number of bytes written, or `usize::MAX` on error.
- `EngineHandle` is opaque; create with `engine_new`, destroy with `engine_free`.
  Handles are `Send` but not thread-safe for concurrent writes without external sync.

Compile targets:
  cargo build -p engine-ffi --release
  → target/release/libengine_ffi.so   (cdylib)
  → target/release/libengine_ffi.a    (staticlib)
*/

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use engine_core::Engine;

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

pub struct EngineHandle {
    engine: Engine,
}

/// Create a new engine with the default policy.
/// Returns a heap-allocated handle; caller must call `engine_free` when done.
#[no_mangle]
pub unsafe extern "C" fn engine_new() -> *mut EngineHandle {
    let handle = Box::new(EngineHandle {
        engine: Engine::with_default_policy(),
    });
    Box::into_raw(handle)
}

/// Free an engine handle previously created by `engine_new`.
#[no_mangle]
pub unsafe extern "C" fn engine_free(handle: *mut EngineHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

// ---------------------------------------------------------------------------
// Mask
// ---------------------------------------------------------------------------

/// Mask sensitive entities in `text`.
///
/// Writes the masked text into `out_buf[0..out_len]` and the correlation ID
/// into `corr_id_buf[0..corr_id_len]`.
///
/// Returns 0 on success, -1 on error (buffer too small, invalid UTF-8, etc.).
#[no_mangle]
pub unsafe extern "C" fn engine_mask(
    handle: *const EngineHandle,
    text: *const c_char,
    out_buf: *mut c_char,
    out_len: *mut usize,
    corr_id_buf: *mut c_char,
    corr_id_len: *mut usize,
) -> c_int {
    let handle = match handle.as_ref() {
        Some(h) => h,
        None => return -1,
    };

    let input = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let result = handle.engine.mask(input, None, None);

    // Write masked text.
    let masked_c = match CString::new(result.text) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let masked_bytes = masked_c.as_bytes_with_nul();
    let buf_cap = *out_len;
    if masked_bytes.len() > buf_cap {
        return -1;
    }
    ptr::copy_nonoverlapping(
        masked_bytes.as_ptr() as *const c_char,
        out_buf,
        masked_bytes.len(),
    );
    *out_len = masked_bytes.len() - 1; // exclude null terminator

    // Write correlation ID.
    let cid_c = match CString::new(result.correlation_id) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let cid_bytes = cid_c.as_bytes_with_nul();
    let cid_cap = *corr_id_len;
    if cid_bytes.len() > cid_cap {
        return -1;
    }
    ptr::copy_nonoverlapping(
        cid_bytes.as_ptr() as *const c_char,
        corr_id_buf,
        cid_bytes.len(),
    );
    *corr_id_len = cid_bytes.len() - 1;

    0
}

// ---------------------------------------------------------------------------
// Rehydrate (batch)
// ---------------------------------------------------------------------------

/// Rehydrate placeholders in `text` using the vault entry for `correlation_id`.
///
/// Writes the rehydrated text into `out_buf[0..out_len]`.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn engine_rehydrate(
    handle: *const EngineHandle,
    text: *const c_char,
    correlation_id: *const c_char,
    out_buf: *mut c_char,
    out_len: *mut usize,
) -> c_int {
    let handle = match handle.as_ref() {
        Some(h) => h,
        None => return -1,
    };

    let input = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let cid = match CStr::from_ptr(correlation_id).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let result = handle.engine.rehydrate(input, cid, None);

    let out_c = match CString::new(result.text) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let out_bytes = out_c.as_bytes_with_nul();
    let buf_cap = *out_len;
    if out_bytes.len() > buf_cap {
        return -1;
    }
    ptr::copy_nonoverlapping(
        out_bytes.as_ptr() as *const c_char,
        out_buf,
        out_bytes.len(),
    );
    *out_len = out_bytes.len() - 1;

    0
}

// ---------------------------------------------------------------------------
// Vault deletion (right-to-erasure)
// ---------------------------------------------------------------------------

/// Delete the vault entry for `correlation_id`. Returns 1 if deleted, 0 if not found.
#[no_mangle]
pub unsafe extern "C" fn engine_delete_vault_entry(
    handle: *const EngineHandle,
    correlation_id: *const c_char,
) -> c_int {
    let handle = match handle.as_ref() {
        Some(h) => h,
        None => return -1,
    };
    let cid = match CStr::from_ptr(correlation_id).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    if handle.engine.delete_vault_entry(cid) {
        1
    } else {
        0
    }
}
