// This module provides interfaces for the zero-knowledge circuit and keys

pub(crate) mod error;
pub(crate) mod iden3calc;
pub(crate) mod qap;

mod backend;
mod graph;
mod secret_fr;
mod types;
mod zkey;

pub use backend::ArkGroth16Backend;
#[cfg(not(target_arch = "wasm32"))]
pub use graph::{default_graph_multi, default_graph_single};
pub use graph::{graph_from_raw, Graph};
pub(crate) use secret_fr::FrOrSecret;
pub use secret_fr::SecretFr;
pub use types::{
    Curve, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective, PartialProof, Proof,
    ProvingKey, VerifyingKey, Zkey, DEFAULT_MAX_OUT, DEFAULT_TREE_DEPTH,
};
pub use zkey::zkey_from_raw;
#[cfg(not(target_arch = "wasm32"))]
pub use zkey::{default_zkey_multi, default_zkey_single};
