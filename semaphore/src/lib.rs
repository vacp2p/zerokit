#![allow(clippy::multiple_crate_versions)]

pub mod circuit;
pub mod protocol;

#[cfg(feature = "dylib")]
pub use circuit::initialize;
