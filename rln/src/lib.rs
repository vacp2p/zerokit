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

// Feature validation for incompatible combinations
#[cfg(all(feature = "fullmerkletree", feature = "optimalmerkletree"))]
compile_error!("Cannot enable both fullmerkletree and optimalmerkletree");

#[cfg(all(feature = "fullmerkletree", feature = "pmtree-ft"))]
compile_error!("Cannot enable both fullmerkletree and pmtree-ft");

#[cfg(all(feature = "optimalmerkletree", feature = "pmtree-ft"))]
compile_error!("Cannot enable both optimalmerkletree and pmtree-ft");

#[cfg(all(
    feature = "stateless",
    any(
        feature = "fullmerkletree",
        feature = "optimalmerkletree",
        feature = "pmtree-ft"
    )
))]
compile_error!("Cannot enable any merkletree features with stateless");
