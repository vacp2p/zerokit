#![allow(non_camel_case_types)]

use num_bigint::BigInt;
use safer_ffi::{boxed::Box_, derive_ReprC, ffi_export, prelude::repr_c};
#[cfg(not(feature = "stateless"))]
use {safer_ffi::prelude::char_p, std::fs::File, std::io::Read};

use super::ffi_utils::{CBoolResult, CFr, CResult};
use crate::prelude::*;

#[cfg(not(feature = "stateless"))]
const MAX_CONFIG_SIZE: u64 = 1024 * 1024; // 1MB

// FFI_RLN

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLN(pub(crate) RLN);

// RLN initialization APIs

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_rln_new(
    tree_depth: usize,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let config_str = File::open(config_path.to_str())
        .and_then(|mut file| {
            let metadata = file.metadata()?;
            if metadata.len() > MAX_CONFIG_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Config file too large: {} bytes (max {} bytes)",
                        metadata.len(),
                        MAX_CONFIG_SIZE
                    ),
                ));
            }
            let mut s = String::new();
            file.read_to_string(&mut s)?;
            Ok(s)
        })
        .unwrap_or_default();

    match RLN::new(tree_depth, config_str.as_str()) {
        Ok(rln) => CResult {
            ok: Some(Box_::new(FFI_RLN(rln))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi_rln_new() -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    match RLN::new() {
        Ok(rln) => CResult {
            ok: Some(Box_::new(FFI_RLN(rln))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_rln_new_with_params(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let config_str = File::open(config_path.to_str())
        .and_then(|mut file| {
            let metadata = file.metadata()?;
            if metadata.len() > MAX_CONFIG_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Config file too large: {} bytes (max {} bytes)",
                        metadata.len(),
                        MAX_CONFIG_SIZE
                    ),
                ));
            }
            let mut s = String::new();
            file.read_to_string(&mut s)?;
            Ok(s)
        })
        .unwrap_or_default();

    match RLN::new_with_params(
        tree_depth,
        zkey_data.to_vec(),
        graph_data.to_vec(),
        config_str.as_str(),
    ) {
        Ok(rln) => CResult {
            ok: Some(Box_::new(FFI_RLN(rln))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi_rln_new_with_params(
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    match RLN::new_with_params(zkey_data.to_vec(), graph_data.to_vec()) {
        Ok(rln) => CResult {
            ok: Some(Box_::new(FFI_RLN(rln))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_free(rln: repr_c::Box<FFI_RLN>) {
    drop(rln);
}

// RLNProof

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNProof(pub(crate) RLNProof);

#[ffi_export]
pub fn ffi_rln_proof_get_values(
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> repr_c::Box<FFI_RLNProofValues> {
    Box_::new(FFI_RLNProofValues(rln_proof.0.proof_values))
}

#[ffi_export]
pub fn ffi_rln_proof_to_bytes_le(
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln_proof_to_bytes_le(&rln_proof.0) {
        Ok(bytes) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_to_bytes_be(
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln_proof_to_bytes_be(&rln_proof.0) {
        Ok(bytes) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_proof(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match bytes_le_to_rln_proof(bytes) {
        Ok((rln_proof, _)) => CResult {
            ok: Some(Box_::new(FFI_RLNProof(rln_proof))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_be_to_rln_proof(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match bytes_be_to_rln_proof(bytes) {
        Ok((rln_proof, _)) => CResult {
            ok: Some(Box_::new(FFI_RLNProof(rln_proof))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_free(rln_proof: repr_c::Box<FFI_RLNProof>) {
    drop(rln_proof);
}

// RLNWitnessInput

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNWitnessInput(pub(crate) RLNWitnessInput);

#[ffi_export]
pub fn ffi_rln_witness_input_new(
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_id: &CFr,
    path_elements: &repr_c::Vec<CFr>,
    identity_path_index: &repr_c::Vec<u8>,
    x: &CFr,
    external_nullifier: &CFr,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    let mut identity_secret_fr = identity_secret.0;
    let path_elements: Vec<Fr> = path_elements.iter().map(|cfr| cfr.0).collect();
    let identity_path_index: Vec<u8> = identity_path_index.iter().copied().collect();
    match RLNWitnessInput::new(
        IdSecret::from(&mut identity_secret_fr),
        user_message_limit.0,
        message_id.0,
        path_elements,
        identity_path_index,
        x.0,
        external_nullifier.0,
    ) {
        Ok(witness) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(witness))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_to_bytes_le(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln_witness_to_bytes_le(&witness.0) {
        Ok(bytes) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_to_bytes_be(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln_witness_to_bytes_be(&witness.0) {
        Ok(bytes) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_witness(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match bytes_le_to_rln_witness(bytes) {
        Ok((witness, _)) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(witness))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_be_to_rln_witness(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match bytes_be_to_rln_witness(bytes) {
        Ok((witness, _)) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(witness))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_to_bigint_json(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::String, repr_c::String> {
    match rln_witness_to_bigint_json(&witness.0) {
        Ok(json) => CResult {
            ok: Some(json.to_string().into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_free(witness: repr_c::Box<FFI_RLNWitnessInput>) {
    drop(witness);
}

// RLNProofValues

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNProofValues(pub(crate) RLNProofValues);

#[ffi_export]
pub fn ffi_rln_proof_values_get_y(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Box<CFr> {
    CFr::from(pv.0.y).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_nullifier(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> repr_c::Box<CFr> {
    CFr::from(pv.0.nullifier).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_root(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Box<CFr> {
    CFr::from(pv.0.root).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_x(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Box<CFr> {
    CFr::from(pv.0.x).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_external_nullifier(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> repr_c::Box<CFr> {
    CFr::from(pv.0.external_nullifier).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_to_bytes_le(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Vec<u8> {
    rln_proof_values_to_bytes_le(&pv.0).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_to_bytes_be(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Vec<u8> {
    rln_proof_values_to_bytes_be(&pv.0).into()
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_proof_values(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProofValues>, repr_c::String> {
    match bytes_le_to_rln_proof_values(bytes) {
        Ok((pv, _)) => CResult {
            ok: Some(Box_::new(FFI_RLNProofValues(pv))),
            err: None,
        },
        Err(e) => CResult {
            ok: None,
            err: Some(format!("{:?}", e).into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_be_to_rln_proof_values(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProofValues>, repr_c::String> {
    match bytes_be_to_rln_proof_values(bytes) {
        Ok((pv, _)) => CResult {
            ok: Some(Box_::new(FFI_RLNProofValues(pv))),
            err: None,
        },
        Err(e) => CResult {
            ok: None,
            err: Some(format!("{:?}", e).into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_free(proof_values: repr_c::Box<FFI_RLNProofValues>) {
    drop(proof_values);
}

// Proof generation APIs

#[ffi_export]
pub fn ffi_generate_rln_proof(
    rln: &repr_c::Box<FFI_RLN>,
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match rln.0.generate_rln_proof(&witness.0) {
        Ok((proof, proof_values)) => {
            let rln_proof = RLNProof {
                proof_values,
                proof,
            };
            CResult {
                ok: Some(Box_::new(FFI_RLNProof(rln_proof))),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_generate_rln_proof_with_witness(
    rln: &repr_c::Box<FFI_RLN>,
    calculated_witness: &repr_c::Vec<repr_c::String>,
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    let calculated_witness_bigint: Result<Vec<BigInt>, _> = calculated_witness
        .iter()
        .map(|s| {
            let s_str = unsafe { std::str::from_utf8_unchecked(s.as_bytes()) };
            s_str.parse::<BigInt>()
        })
        .collect();

    let calculated_witness_bigint = match calculated_witness_bigint {
        Ok(w) => w,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(format!("Failed to parse witness: {}", err).into()),
            }
        }
    };

    match rln
        .0
        .generate_rln_proof_with_witness(calculated_witness_bigint, &witness.0)
    {
        Ok((proof, proof_values)) => {
            let rln_proof = RLNProof {
                proof_values,
                proof,
            };
            CResult {
                ok: Some(Box_::new(FFI_RLNProof(rln_proof))),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// Proof verification APIs

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi_verify_rln_proof(
    rln: &repr_c::Box<FFI_RLN>,
    rln_proof: &repr_c::Box<FFI_RLNProof>,
    x: &CFr,
) -> CBoolResult {
    match rln
        .0
        .verify_rln_proof(&rln_proof.0.proof, &rln_proof.0.proof_values, &x.0)
    {
        Ok(verified) => CBoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_verify_with_roots(
    rln: &repr_c::Box<FFI_RLN>,
    rln_proof: &repr_c::Box<FFI_RLNProof>,
    roots: &repr_c::Vec<CFr>,
    x: &CFr,
) -> CBoolResult {
    let roots_fr: Vec<Fr> = roots.iter().map(|cfr| cfr.0).collect();

    match rln.0.verify_with_roots(
        &rln_proof.0.proof,
        &rln_proof.0.proof_values,
        &x.0,
        &roots_fr,
    ) {
        Ok(verified) => CBoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

// Identity secret recovery API

#[ffi_export]
pub fn ffi_recover_id_secret(
    proof_values_1: &repr_c::Box<FFI_RLNProofValues>,
    proof_values_2: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match recover_id_secret(&proof_values_1.0, &proof_values_2.0) {
        Ok(secret) => CResult {
            ok: Some(Box_::new(CFr::from(*secret))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}
