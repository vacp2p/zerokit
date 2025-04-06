// This crate provides interfaces for the zero-knowledge circuit and keys

use std::collections::HashMap;
use ::lazy_static::lazy_static;
use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use cfg_if::cfg_if;
use circom_witnesscalc::{calc_witness, deserialize_inputs, graph, Error, InputSignalsInfo};
use circom_witnesscalc::graph::Node;
use circom_witnesscalc::storage::deserialize_witnesscalc_graph;
use color_eyre::{Report, Result};
use ruint::aliases::U256;
// use crate::iden3calc::calc_witness;
use crate::iden3calc::graph::{fr_to_u256, u256_to_fr};

#[cfg(feature = "arkzkey")]
use {
    ark_ff::Field, ark_serialize::CanonicalDeserialize, ark_serialize::CanonicalSerialize,
    color_eyre::eyre::WrapErr,
};

#[cfg(not(feature = "arkzkey"))]
use {ark_circom::read_zkey, std::io::Cursor};

#[cfg(feature = "arkzkey")]
pub const ARKZKEY_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln_final.arkzkey");

pub const ZKEY_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln_final.zkey");
const GRAPH_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/graph.bin");

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
pub fn zkey_from_raw(zkey_data: &[u8]) -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> {
    if zkey_data.is_empty() {
        return Err(Report::msg("No proving key found!"));
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
pub fn zkey_from_folder() -> &'static (ProvingKey<Curve>, ConstraintMatrices<Fr>) {
    &ZKEY
}

// Loads the verification key from a bytes vector
pub fn vk_from_raw(zkey_data: &[u8]) -> Result<VerifyingKey<Curve>> {
    if !zkey_data.is_empty() {
        let (proving_key, _matrices) = zkey_from_raw(zkey_data)?;
        return Ok(proving_key.vk);
    }

    Err(Report::msg("No proving/verification key found!"))
}

// Checks verification key to be correct with respect to proving key
pub fn check_vk_from_zkey(verifying_key: VerifyingKey<Curve>) -> Result<()> {
    let (proving_key, _matrices) = zkey_from_folder();
    if proving_key.vk == verifying_key {
        Ok(())
    } else {
        Err(Report::msg("verifying_keys are not equal"))
    }
}

pub fn calculate_rln_witness<I: IntoIterator<Item = (String, Vec<Fr>)>>(
    inputs: I,
    graph_data: &[u8],
) -> Vec<Fr> {
    // calc_witness(inputs, graph_data)
    let res = calc_witness_2(inputs, graph_data).unwrap();
    res.iter().map(|v| u256_to_fr(&v)).collect()
}

pub fn calc_witness_2<I: IntoIterator<Item = (String, Vec<Fr>)>>(inputs: I, graph_data: &[u8]) -> std::result::Result<Vec<U256>, Error> {

    // HashMap<String, U256>
    // let inputs = deserialize_inputs(inputs.as_bytes())?;

    let inputs: HashMap<String, Vec<U256>> = inputs
        .into_iter()
        .map(|(key, value)| (key, value.iter().map(fr_to_u256).collect()))
        .collect();

    let (nodes, signals, input_mapping): (Vec<Node>, Vec<usize>, InputSignalsInfo) =
        deserialize_witnesscalc_graph(std::io::Cursor::new(graph_data)).unwrap();

    let mut inputs_buffer = get_inputs_buffer(get_inputs_size(&nodes));
    populate_inputs(&inputs, &input_mapping, &mut inputs_buffer);

    Ok(graph::evaluate(&nodes, inputs_buffer.as_slice(), &signals))
}

fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}

fn get_inputs_size(nodes: &[Node]) -> usize {
    let mut start = false;
    let mut max_index = 0usize;
    for &node in nodes.iter() {
        if let Node::Input(i) = node {
            if i > max_index {
                max_index = i;
            }
            start = true
        } else if start {
            break;
        }
    }
    max_index + 1
}

fn populate_inputs(
    input_list: &HashMap<String, Vec<U256>>, inputs_info: &InputSignalsInfo,
    input_buffer: &mut [U256]) {
    for (key, value) in input_list {
        let (offset, len) = inputs_info[key];
        if len != value.len() {
            panic!("Invalid input length for {}", key);
        }
        // println!("input {}, offset {}, len {}", key, offset, len);

        for (i, v) in value.iter().enumerate() {
            input_buffer[offset + i] = *v;
        }
    }
}

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
) -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> {
    if arkzkey_data.is_empty() {
        return Err(Report::msg("No proving key found!"));
    }

    let mut cursor = std::io::Cursor::new(arkzkey_data);

    let serialized_proving_key =
        SerializableProvingKey::deserialize_uncompressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize proving key")?;

    let serialized_constraint_matrices =
        SerializableConstraintMatrices::deserialize_uncompressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize constraint matrices")?;

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
