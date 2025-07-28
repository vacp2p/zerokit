pub mod circuit;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;
pub mod hashers;
#[cfg(feature = "pmtree-ft")]
pub mod pm_tree_adapter;
#[cfg(not(feature = "stateless"))]
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
compile_error!("Only one of `fullmerkletree`, `optimalmerkletree`, or `pmtree-ft` can be enabled at a time.");

#[cfg(all(
    feature = "stateless",
    any(
        feature = "fullmerkletree",
        feature = "optimalmerkletree",
        feature = "pmtree-ft"
    )
))]
compile_error!("Cannot enable any Merkle tree features with stateless");
