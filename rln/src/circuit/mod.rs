// This crate provides interfaces for the zero-knowledge circuit and keys

pub mod error;
pub mod iden3calc;
pub mod qap;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::LazyLock;

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ff::Field;
use ark_groth16::{
    Proof as ArkProof, ProvingKey as ArkProvingKey, VerifyingKey as ArkVerifyingKey,
};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::circuit::error::ZKeyReadError;

#[cfg(not(target_arch = "wasm32"))]
const GRAPH_BYTES: &[u8] = include_bytes!("../../resources/tree_depth_20/graph.bin");

#[cfg(not(target_arch = "wasm32"))]
const ARKZKEY_BYTES: &[u8] = include_bytes!("../../resources/tree_depth_20/rln_final.arkzkey");

#[cfg(not(target_arch = "wasm32"))]
static ARKZKEY: LazyLock<Zkey> = LazyLock::new(|| {
    read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES).expect("Failed to read arkzkey")
});

pub const DEFAULT_TREE_DEPTH: usize = 20;
pub const COMPRESS_PROOF_SIZE: usize = 128;

// The following types define the pairing friendly elliptic curve, the underlying finite fields and groups default to this module
// Note that proofs are serialized assuming Fr to be 4x8 = 32 bytes in size. Hence, changing to a curve with different encoding will make proof verification to fail

/// BN254 pairing-friendly elliptic curve.
pub type Curve = Bn254;

/// Scalar field Fr of the BN254 curve.
pub type Fr = ArkFr;

/// Base field Fq of the BN254 curve.
pub type Fq = ArkFq;

/// Quadratic extension field element for the BN254 curve.
pub type Fq2 = ArkFq2;

/// Affine representation of a G1 group element on the BN254 curve.
pub type G1Affine = ArkG1Affine;

/// Projective representation of a G1 group element on the BN254 curve.
pub type G1Projective = ArkG1Projective;

/// Affine representation of a G2 group element on the BN254 curve.
pub type G2Affine = ArkG2Affine;

/// Projective representation of a G2 group element on the BN254 curve.
pub type G2Projective = ArkG2Projective;

/// Groth16 proof for the BN254 curve.
pub type Proof = ArkProof<Curve>;

/// Proving key for the Groth16 proof system.
pub type ProvingKey = ArkProvingKey<Curve>;

/// Combining the proving key and constraint matrices.
pub type Zkey = (ArkProvingKey<Curve>, ConstraintMatrices<Fr>);

/// Verifying key for the Groth16 proof system.
pub type VerifyingKey = ArkVerifyingKey<Curve>;

/// Loads the zkey from raw bytes
pub fn zkey_from_raw(zkey_data: &[u8]) -> Result<Zkey, ZKeyReadError> {
    if zkey_data.is_empty() {
        return Err(ZKeyReadError::EmptyBytes);
    }

    let proving_key_and_matrices = read_arkzkey_from_bytes_uncompressed(zkey_data)?;

    Ok(proving_key_and_matrices)
}

// Loads default zkey from folder
#[cfg(not(target_arch = "wasm32"))]
pub fn zkey_from_folder() -> &'static Zkey {
    &ARKZKEY
}

// Loads default graph from folder
#[cfg(not(target_arch = "wasm32"))]
pub fn graph_from_folder() -> &'static [u8] {
    GRAPH_BYTES
}

// The following functions and structs are based on code from ark-zkey:
// https://github.com/zkmopro/ark-zkey/blob/main/src/lib.rs#L106

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
struct SerializableProvingKey(ArkProvingKey<Curve>);

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
struct SerializableConstraintMatrices<F: Field> {
    num_instance_variables: usize,
    num_witness_variables: usize,
    num_constraints: usize,
    a_num_non_zero: usize,
    b_num_non_zero: usize,
    c_num_non_zero: usize,
    a: SerializableMatrix<F>,
    b: SerializableMatrix<F>,
    c: SerializableMatrix<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
struct SerializableMatrix<F: Field> {
    pub data: Vec<Vec<(F, usize)>>,
}

fn read_arkzkey_from_bytes_uncompressed(arkzkey_data: &[u8]) -> Result<Zkey, ZKeyReadError> {
    if arkzkey_data.is_empty() {
        return Err(ZKeyReadError::EmptyBytes);
    }

    let mut cursor = std::io::Cursor::new(arkzkey_data);

    let serialized_proving_key =
        SerializableProvingKey::deserialize_uncompressed_unchecked(&mut cursor)?;

    let serialized_constraint_matrices =
        SerializableConstraintMatrices::deserialize_uncompressed_unchecked(&mut cursor)?;

    let proving_key: ProvingKey = serialized_proving_key.0;
    let constraint_matrices: ConstraintMatrices<Fr> = ConstraintMatrices {
        num_instance_variables: serialized_constraint_matrices.num_instance_variables,
        num_witness_variables: serialized_constraint_matrices.num_witness_variables,
        num_constraints: serialized_constraint_matrices.num_constraints,
        a_num_non_zero: serialized_constraint_matrices.a_num_non_zero,
        b_num_non_zero: serialized_constraint_matrices.b_num_non_zero,
        c_num_non_zero: serialized_constraint_matrices.c_num_non_zero,
        a: serialized_constraint_matrices.a.data,
        b: serialized_constraint_matrices.b.data,
        c: serialized_constraint_matrices.c.data,
    };
    let zkey = (proving_key, constraint_matrices);

    Ok(zkey)
}
