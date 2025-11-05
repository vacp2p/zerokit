pub mod circuit;
pub mod error;
pub mod ffi;
pub mod hashers;
pub mod pm_tree_adapter;
pub mod poseidon_tree;
pub mod protocol;
pub mod public;
#[cfg(test)]
pub mod public_api_tests;
pub mod utils;

// Ensure that only one Merkle tree feature is enabled at a time
#[cfg(any(
    all(feature = "fullmerkletree", feature = "optimalmerkletree"),
    all(feature = "fullmerkletree", feature = "pmtree-ft"),
    all(feature = "optimalmerkletree", feature = "pmtree-ft"),
))]
compile_error!(
    "Only one of `fullmerkletree`, `optimalmerkletree`, or `pmtree-ft` can be enabled at a time."
);

// Ensure that the `stateless` feature is not enabled with any Merkle tree features
#[cfg(all(
    feature = "stateless",
    any(
        feature = "fullmerkletree",
        feature = "optimalmerkletree",
        feature = "pmtree-ft"
    )
))]
compile_error!("Cannot enable any Merkle tree features with stateless");
