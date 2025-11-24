#![allow(non_camel_case_types)]

use super::ffi_utils::{CBoolResult, CFr, CResult};
use crate::{
    circuit::{graph_from_folder, zkey_from_folder, zkey_from_raw, Curve, Fr},
    protocol::{
        compute_id_secret, generate_proof, proof_values_from_witness, verify_proof, RLNProofValues,
        RLNWitnessInput,
    },
    utils::IdSecret,
};
use ark_groth16::{Proof as ArkProof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use safer_ffi::{boxed::Box_, derive_ReprC, ffi_export, prelude::repr_c};

#[cfg(not(feature = "stateless"))]
use {
    crate::poseidon_tree::PoseidonTree,
    safer_ffi::prelude::char_p,
    std::{fs::File, io::Read, str::FromStr},
    utils::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree},
};

// FFI_RLN

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLN {
    pub(crate) proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    pub(crate) tree: PoseidonTree,
}

// RLN initialization APIs

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_rln_new(
    tree_depth: usize,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let tree_config = match File::open(config_path.to_str()).and_then(|mut file| {
        let mut config_str = String::new();
        file.read_to_string(&mut config_str)?;
        Ok(config_str)
    }) {
        Ok(config_str) if !config_str.is_empty() => {
            match <PoseidonTree as ZerokitMerkleTree>::Config::from_str(&config_str) {
                Ok(config) => config,
                Err(err) => {
                    return CResult {
                        ok: None,
                        err: Some(err.to_string().into()),
                    };
                }
            }
        }
        _ => <PoseidonTree as ZerokitMerkleTree>::Config::default(),
    };

    let proving_key = zkey_from_folder().to_owned();
    let graph_data = graph_from_folder().to_owned();

    // We compute a default empty tree
    let tree = match PoseidonTree::new(
        tree_depth,
        <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
        tree_config,
    ) {
        Ok(tree) => tree,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let rln = FFI_RLN {
        proving_key: proving_key.to_owned(),
        graph_data: graph_data.to_vec(),
        #[cfg(not(feature = "stateless"))]
        tree,
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi_rln_new() -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let proving_key = zkey_from_folder().to_owned();
    let graph_data = graph_from_folder().to_owned();

    let rln = FFI_RLN {
        proving_key: proving_key.to_owned(),
        graph_data: graph_data.to_vec(),
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_rln_new_with_params(
    tree_depth: usize,
    zkey_buffer: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let tree_config = match File::open(config_path.to_str()).and_then(|mut file| {
        let mut config_str = String::new();
        file.read_to_string(&mut config_str)?;
        Ok(config_str)
    }) {
        Ok(config_str) if !config_str.is_empty() => {
            match <PoseidonTree as ZerokitMerkleTree>::Config::from_str(&config_str) {
                Ok(config) => config,
                Err(err) => {
                    return CResult {
                        ok: None,
                        err: Some(err.to_string().into()),
                    };
                }
            }
        }
        _ => <PoseidonTree as ZerokitMerkleTree>::Config::default(),
    };

    let proving_key = match zkey_from_raw(zkey_buffer) {
        Ok(pk) => pk,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    // We compute a default empty tree
    let tree = match PoseidonTree::new(
        tree_depth,
        <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
        tree_config,
    ) {
        Ok(tree) => tree,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let rln = FFI_RLN {
        proving_key,
        graph_data: graph_data.to_vec(),
        #[cfg(not(feature = "stateless"))]
        tree,
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi_new_with_params(
    zkey_buffer: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let proving_key = match zkey_from_raw(zkey_buffer) {
        Ok(pk) => pk,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let rln = FFI_RLN {
        proving_key,
        graph_data: graph_data.to_vec(),
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[ffi_export]
pub fn ffi_rln_free(rln: repr_c::Box<FFI_RLN>) {
    drop(rln);
}

// RLNProof

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNProof {
    pub(crate) proof: ArkProof<Curve>,
    pub(crate) proof_values: RLNProofValues,
}

#[ffi_export]
pub fn ffi_rln_proof_free(rln_proof: repr_c::Box<FFI_RLNProof>) {
    drop(rln_proof);
}

// Proof generation APIs

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_generate_rln_proof(
    rln: &repr_c::Box<FFI_RLN>,
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_id: &CFr,
    x: &CFr,
    external_nullifier: &CFr,
    leaf_index: usize,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    let proof = match rln.tree.proof(leaf_index) {
        Ok(proof) => proof,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let path_elements: Vec<Fr> = proof.get_path_elements();
    let identity_path_index: Vec<u8> = proof.get_path_index();

    let mut identity_secret_fr = identity_secret.0;
    let rln_witness = match RLNWitnessInput::new(
        IdSecret::from(&mut identity_secret_fr),
        user_message_limit.0,
        message_id.0,
        path_elements,
        identity_path_index,
        x.0,
        external_nullifier.0,
    ) {
        Ok(witness) => witness,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof_values = match proof_values_from_witness(&rln_witness) {
        Ok(pv) => pv,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof = match generate_proof(&rln.proving_key, &rln_witness, &rln.graph_data) {
        Ok(proof) => proof,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    CResult {
        ok: Some(Box_::new(FFI_RLNProof {
            proof_values,
            proof,
        })),
        err: None,
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi_generate_rln_proof_stateless(
    rln: &repr_c::Box<FFI_RLN>,
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_id: &CFr,
    path_elements: &repr_c::Vec<CFr>,
    identity_path_index: &repr_c::Vec<u8>,
    x: &CFr,
    external_nullifier: &CFr,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    let mut identity_secret_fr = identity_secret.0;
    let path_elements: Vec<Fr> = path_elements.iter().map(|cfr| cfr.0).collect();
    let identity_path_index: Vec<u8> = identity_path_index.iter().copied().collect();
    let rln_witness = match RLNWitnessInput::new(
        IdSecret::from(&mut identity_secret_fr),
        user_message_limit.0,
        message_id.0,
        path_elements,
        identity_path_index,
        x.0,
        external_nullifier.0,
    ) {
        Ok(witness) => witness,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof_values = match proof_values_from_witness(&rln_witness) {
        Ok(pv) => pv,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof = match generate_proof(&rln.proving_key, &rln_witness, &rln.graph_data) {
        Ok(proof) => proof,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    CResult {
        ok: Some(Box_::new(FFI_RLNProof {
            proof_values,
            proof,
        })),
        err: None,
    }
}

// Proof verification APIs

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_verify_rln_proof(
    rln: &repr_c::Box<FFI_RLN>,
    proof: &repr_c::Box<FFI_RLNProof>,
    x: &CFr,
) -> CBoolResult {
    // Verify the root
    if rln.tree.root() != proof.proof_values.root {
        return CBoolResult {
            ok: false,
            err: Some("Invalid root".to_string().into()),
        };
    }

    // Verify the signal
    if *x != proof.proof_values.x {
        return CBoolResult {
            ok: false,
            err: Some("Invalid signal".to_string().into()),
        };
    }

    // Verify the proof
    match verify_proof(&rln.proving_key.0.vk, &proof.proof, &proof.proof_values) {
        Ok(proof_verified) => {
            if !proof_verified {
                return CBoolResult {
                    ok: false,
                    err: Some("Invalid proof".to_string().into()),
                };
            }
        }
        Err(err) => {
            return CBoolResult {
                ok: false,
                err: Some(err.to_string().into()),
            };
        }
    };

    // All verifications passed
    CBoolResult {
        ok: true,
        err: None,
    }
}

#[ffi_export]
pub fn ffi_verify_with_roots(
    rln: &repr_c::Box<FFI_RLN>,
    proof: &repr_c::Box<FFI_RLNProof>,
    roots: &repr_c::Vec<CFr>,
    x: &CFr,
) -> CBoolResult {
    // Verify the root
    if !roots.is_empty() && !roots.iter().any(|root| root.0 == proof.proof_values.root) {
        return CBoolResult {
            ok: false,
            err: Some("Invalid root".to_string().into()),
        };
    }

    // Verify the signal
    if *x != proof.proof_values.x {
        return CBoolResult {
            ok: false,
            err: Some("Invalid signal".to_string().into()),
        };
    }

    // Verify the proof
    match verify_proof(&rln.proving_key.0.vk, &proof.proof, &proof.proof_values) {
        Ok(proof_verified) => {
            if !proof_verified {
                return CBoolResult {
                    ok: false,
                    err: Some("Invalid proof".to_string().into()),
                };
            }
        }
        Err(err) => {
            return CBoolResult {
                ok: false,
                err: Some(err.to_string().into()),
            };
        }
    };

    // All verifications passed
    CBoolResult {
        ok: true,
        err: None,
    }
}

// Identity secret recovery API

#[ffi_export]
pub fn ffi_recover_id_secret(
    proof_1: &repr_c::Box<FFI_RLNProof>,
    proof_2: &repr_c::Box<FFI_RLNProof>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    let external_nullifier_1 = proof_1.proof_values.external_nullifier;
    let external_nullifier_2 = proof_2.proof_values.external_nullifier;

    // We continue only if the proof values are for the same external nullifier
    if external_nullifier_1 != external_nullifier_2 {
        return CResult {
            ok: None,
            err: Some("External nullifiers do not match".to_string().into()),
        };
    }

    // We extract the two shares
    let share1 = (proof_1.proof_values.x, proof_1.proof_values.y);
    let share2 = (proof_2.proof_values.x, proof_2.proof_values.y);

    // We recover the secret
    let recovered_identity_secret_hash = match compute_id_secret(share1, share2) {
        Ok(secret) => secret,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    CResult {
        ok: Some(CFr::from(*recovered_identity_secret_hash).into()),
        err: None,
    }
}
