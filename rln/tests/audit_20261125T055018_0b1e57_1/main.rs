//! Proof for finding 20261125T055018-0b1e57/1.
//!
//! Zerokit API, "Slashing":
//!   "FFI: `ffi_rln_recover_id_secret()`, `ffi_rln_compute_id_secret()`
//!    (the recovered secret is returned as a plain field element deliberately,
//!    since slashing is a reveal)."
//!
//! FFI-Specific Notes: "Field elements are wrapped as `FFI_Fr`; secrets as the
//! opaque `FFI_SecretFr`".
//!
//! So both functions must hand back an `FFI_Fr`. These tests are generic over
//! the returned type, so they compile both before and after a fix.

use std::any::type_name;

use rln::{
    ffi::{ffi_rln::*, ffi_utils::*},
    prelude::*,
};
use safer_ffi::layout::ReprC;

fn ok_type<T: ReprC, E: ReprC>(_: &FFI_Result<T, E>) -> &'static str {
    type_name::<T>()
}

fn ret_ok_type<A, B, T: ReprC, E: ReprC>(
    _: extern "C" fn(&A, &B) -> FFI_Result<T, E>,
) -> &'static str {
    type_name::<T>()
}

fn is_plain_fr(ty: &str) -> bool {
    ty.contains("FFI_Fr") && !ty.contains("FFI_SecretFr")
}

#[test]
fn compute_id_secret_returns_plain_field_element() {
    // Two Shamir shares of the line y = a0 + x * a1, a0 being the identity secret.
    let a0 = Fr::from(42u32);
    let a1 = Fr::from(7u32);
    let (x1, x2) = (Fr::from(3u32), Fr::from(5u32));
    let (y1, y2) = (a0 + x1 * a1, a0 + x2 * a1);

    let result = ffi_rln_compute_id_secret(
        &FFI_Fr::from(x1),
        &FFI_Fr::from(y1),
        &FFI_Fr::from(x2),
        &FFI_Fr::from(y2),
    );
    assert!(result.err.is_none(), "reconstruction itself must succeed");
    assert!(result.ok.is_some(), "reconstruction itself must succeed");

    let returned = ok_type(&result);
    assert!(
        is_plain_fr(returned),
        "spec: the recovered secret is returned as a plain field element (FFI_Fr); \
         ffi_rln_compute_id_secret returned {returned}"
    );
}

#[test]
fn recover_id_secret_returns_plain_field_element() {
    let returned = ret_ok_type(ffi_rln_recover_id_secret);
    assert!(
        is_plain_fr(returned),
        "spec: the recovered secret is returned as a plain field element (FFI_Fr); \
         ffi_rln_recover_id_secret returns {returned}"
    );
}
