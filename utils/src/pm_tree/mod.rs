// TODO(PR11): maybe we can simplify this by only create wrapper for PmTree in rln module
// and move the sled adapter to rln module as well, since it's only used in rln for now.
// This should be an example of how user can customize the storage layer for PmTree or
// even implement their own tree structure by implementing the same trait of ZerokitMerkleTree.
#![cfg(feature = "pmtree-ft")]

pub mod sled_adapter;

pub use pmtree;
pub use sled::{Config, Mode};
pub use sled_adapter::SledDB;
