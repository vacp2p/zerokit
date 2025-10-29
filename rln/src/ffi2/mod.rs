pub mod ffi_rln;
pub mod ffi_tree;
pub mod ffi_utils;

#[cfg(feature = "headers")]
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder().to_file("rln.h")?.generate()
}
