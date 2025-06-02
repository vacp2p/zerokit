// This crate provides interfaces for the zero-knowledge circuit and keys

pub mod error;
pub mod iden3calc;
pub mod qap;
pub mod zkey;

use ::lazy_static::lazy_static;
use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use cfg_if::cfg_if;

use crate::circuit::error::ZKeyReadError;
use crate::circuit::iden3calc::calc_witness;

#[cfg(feature = "arkzkey")]
use {ark_ff::Field, ark_serialize::CanonicalDeserialize, ark_serialize::CanonicalSerialize};

#[cfg(not(feature = "arkzkey"))]
use {crate::circuit::zkey::read_zkey, std::io::Cursor};

#[cfg(feature = "arkzkey")]
pub const ARKZKEY_BYTES: &[u8] = include_bytes!("../../resources/tree_height_20/rln_final.arkzkey");

pub const ZKEY_BYTES: &[u8] = include_bytes!("../../resources/tree_height_20/rln_final.zkey");

#[cfg(not(target_arch = "wasm32"))]
const GRAPH_BYTES: &[u8] = include_bytes!("../../resources/tree_height_20/graph.bin");

lazy_static! {
    static ref ZKEY: (ProvingKey<Curve>, ConstraintMatrices<Fr>) = {
        cfg_if! {
                if #[cfg(feature = "arkzkey")] {
                    read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES).expect("Failed to read arkzkey")
                } else {
                    let mut reader = Cursor::new(ZKEY_BYTES);
                    read_zkey(&mut reader).expect("Failed to read zkey")
                }
        }
    };
}

pub const TEST_TREE_HEIGHT: usize = 20;

// The following types define the pairing friendly elliptic curve, the underlying finite fields and groups default to this module
// Note that proofs are serialized assuming Fr to be 4x8 = 32 bytes in size. Hence, changing to a curve with different encoding will make proof verification to fail
pub type Curve = Bn254;
pub type Fr = ArkFr;
pub type Fq = ArkFq;
pub type Fq2 = ArkFq2;
pub type G1Affine = ArkG1Affine;
pub type G1Projective = ArkG1Projective;
pub type G2Affine = ArkG2Affine;
pub type G2Projective = ArkG2Projective;

// Loads the proving key using a bytes vector
pub fn zkey_from_raw(
    zkey_data: &[u8],
) -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>), ZKeyReadError> {
    if zkey_data.is_empty() {
        return Err(ZKeyReadError::EmptyBytes);
    }

    let proving_key_and_matrices = match () {
        #[cfg(feature = "arkzkey")]
        () => read_arkzkey_from_bytes_uncompressed(zkey_data)?,
        #[cfg(not(feature = "arkzkey"))]
        () => {
            let mut reader = Cursor::new(zkey_data);
            read_zkey(&mut reader)?
        }
    };

    Ok(proving_key_and_matrices)
}

// Loads the proving key
#[cfg(not(target_arch = "wasm32"))]
pub fn zkey_from_folder() -> &'static (ProvingKey<Curve>, ConstraintMatrices<Fr>) {
    &ZKEY
}

pub fn calculate_rln_witness<I: IntoIterator<Item = (String, Vec<Fr>)>>(
    inputs: I,
    graph_data: &[u8],
) -> Vec<Fr> {
    calc_witness(inputs, graph_data)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn graph_from_folder() -> &'static [u8] {
    GRAPH_BYTES
}

////////////////////////////////////////////////////////
// Functions and structs from [arkz-key](https://github.com/zkmopro/ark-zkey/blob/main/src/lib.rs#L106)
// without print and allow to choose between compressed and uncompressed arkzkey
////////////////////////////////////////////////////////

#[cfg(feature = "arkzkey")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableProvingKey(pub ProvingKey<Bn254>);

#[cfg(feature = "arkzkey")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableConstraintMatrices<F: Field> {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a_num_non_zero: usize,
    pub b_num_non_zero: usize,
    pub c_num_non_zero: usize,
    pub a: SerializableMatrix<F>,
    pub b: SerializableMatrix<F>,
    pub c: SerializableMatrix<F>,
}

#[cfg(feature = "arkzkey")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableMatrix<F: Field> {
    pub data: Vec<Vec<(F, usize)>>,
}

#[cfg(feature = "arkzkey")]
pub fn read_arkzkey_from_bytes_uncompressed(
    arkzkey_data: &[u8],
) -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>), ZKeyReadError> {
    if arkzkey_data.is_empty() {
        return Err(ZKeyReadError::EmptyBytes);
    }

    let mut cursor = std::io::Cursor::new(arkzkey_data);

    let serialized_proving_key =
        SerializableProvingKey::deserialize_uncompressed_unchecked(&mut cursor)?;

    let serialized_constraint_matrices =
        SerializableConstraintMatrices::deserialize_uncompressed_unchecked(&mut cursor)?;

    // Get on right form for API
    let proving_key: ProvingKey<Bn254> = serialized_proving_key.0;
    let constraint_matrices: ConstraintMatrices<ark_bn254::Fr> = ConstraintMatrices {
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

    Ok((proving_key, constraint_matrices))
}
