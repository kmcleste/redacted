//! Integration tests for the C ABI.
//!
//! These call `engine_new` / `engine_mask` / `engine_rehydrate` /
//! `engine_delete_vault_entry` / `engine_free` through their public Rust
//! signatures (identical to the C ABI in terms of types and semantics).

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};

use engine_ffi::{
    engine_delete_vault_entry, engine_free, engine_mask, engine_new, engine_rehydrate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Call `engine_mask` and return (masked_text, correlation_id).
unsafe fn call_mask(handle: *const engine_ffi::EngineHandle, input: &str) -> (String, String) {
    let text_c = CString::new(input).unwrap();
    let mut masked_buf = vec![0u8; 4096];
    let mut masked_len = masked_buf.len();
    let mut cid_buf = vec![0u8; 256];
    let mut cid_len = cid_buf.len();

    let rc = engine_mask(
        handle,
        text_c.as_ptr(),
        masked_buf.as_mut_ptr() as *mut _,
        &mut masked_len,
        cid_buf.as_mut_ptr() as *mut _,
        &mut cid_len,
    );
    assert_eq!(rc, 0, "engine_mask returned error");

    let masked = CStr::from_ptr(masked_buf.as_ptr() as *const _)
        .to_str()
        .unwrap()
        .to_string();
    let cid = CStr::from_ptr(cid_buf.as_ptr() as *const _)
        .to_str()
        .unwrap()
        .to_string();
    (masked, cid)
}

/// Call `engine_rehydrate` and return the rehydrated text.
unsafe fn call_rehydrate(
    handle: *const engine_ffi::EngineHandle,
    text: &str,
    correlation_id: &str,
) -> String {
    let text_c = CString::new(text).unwrap();
    let cid_c = CString::new(correlation_id).unwrap();
    let mut out_buf = vec![0u8; 4096];
    let mut out_len = out_buf.len();

    let rc = engine_rehydrate(
        handle,
        text_c.as_ptr(),
        cid_c.as_ptr(),
        out_buf.as_mut_ptr() as *mut _,
        &mut out_len,
    );
    assert_eq!(rc, 0, "engine_rehydrate returned error");

    CStr::from_ptr(out_buf.as_ptr() as *const _)
        .to_str()
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_null_handle_returns_error() {
    unsafe {
        let mut buf = vec![0u8; 256];
        let mut buf_len = buf.len();
        let mut cid_buf = vec![0u8; 256];
        let mut cid_len = cid_buf.len();
        let text = CString::new("hello").unwrap();

        let rc = engine_mask(
            std::ptr::null(),
            text.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            &mut buf_len,
            cid_buf.as_mut_ptr() as *mut _,
            &mut cid_len,
        );
        assert_eq!(rc, -1);
    }
}

#[test]
fn test_mask_rehydrate_ssn_roundtrip() {
    unsafe {
        let handle = engine_new();
        assert!(!handle.is_null());

        // user@acme.com — non-doc domain, passes the validator.
        let input = "My SSN is 575-82-8889 and email is user@acme.com";
        let (masked, cid) = call_mask(handle as *const _, input);

        assert!(
            masked.contains("[SSN_1]"),
            "expected [SSN_1] in masked text: {masked}"
        );
        assert!(
            masked.contains("[EMAIL_1]"),
            "expected [EMAIL_1] in masked text: {masked}"
        );
        assert!(!masked.contains("575-82-8889"), "SSN should be masked");
        assert!(!masked.contains("user@acme.com"), "email should be masked");

        let rehydrated = call_rehydrate(handle as *const _, &masked, &cid);
        assert!(
            rehydrated.contains("575-82-8889"),
            "expected SSN restored: {rehydrated}"
        );
        assert!(
            rehydrated.contains("user@acme.com"),
            "expected email restored: {rehydrated}"
        );

        engine_free(handle);
    }
}

#[test]
fn test_clean_text_passes_through() {
    unsafe {
        let handle = engine_new();
        assert!(!handle.is_null());

        let input = "No sensitive content here.";
        let (masked, _cid) = call_mask(handle as *const _, input);
        assert_eq!(masked, input, "clean text should be unchanged");

        engine_free(handle);
    }
}

#[test]
fn test_delete_vault_entry() {
    unsafe {
        let handle = engine_new();
        assert!(!handle.is_null());

        let (_masked, cid) = call_mask(handle as *const _, "SSN 575-82-8889");

        let cid_c = CString::new(cid.as_str()).unwrap();

        // First delete — should succeed (return 1).
        let rc = engine_delete_vault_entry(handle as *const _, cid_c.as_ptr());
        assert_eq!(rc, 1, "first delete should return 1 (found and deleted)");

        // Second delete — already gone (return 0).
        let rc = engine_delete_vault_entry(handle as *const _, cid_c.as_ptr());
        assert_eq!(rc, 0, "second delete should return 0 (not found)");

        engine_free(handle);
    }
}

#[test]
fn test_buffer_too_small_returns_error() {
    unsafe {
        let handle = engine_new();
        assert!(!handle.is_null());

        let text = CString::new("SSN 575-82-8889").unwrap();
        let mut tiny_buf = vec![0u8; 2]; // intentionally too small
        let mut buf_len = tiny_buf.len();
        let mut cid_buf = vec![0u8; 256];
        let mut cid_len = cid_buf.len();

        let rc = engine_mask(
            handle as *const _,
            text.as_ptr(),
            tiny_buf.as_mut_ptr() as *mut _,
            &mut buf_len,
            cid_buf.as_mut_ptr() as *mut _,
            &mut cid_len,
        );
        assert_eq!(rc, -1, "small buffer should return -1");

        engine_free(handle);
    }
}
