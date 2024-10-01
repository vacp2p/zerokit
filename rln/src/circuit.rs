// This crate provides interfaces for the zero-knowledge circuit and keys

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalDeserialize;
use cfg_if::cfg_if;
use color_eyre::{Report, Result};

#[cfg(not(target_arch = "wasm32"))]
use {
    ark_circom::WitnessCalculator,
    lazy_static::lazy_static,
    std::sync::{Arc, Mutex},
    wasmer::{Module, Store},
};

#[cfg(feature = "arkzkey")]
use {
    ark_zkey::{read_arkzkey_from_bytes, SerializableConstraintMatrices, SerializableProvingKey},
    color_eyre::eyre::WrapErr,
};

#[cfg(not(feature = "arkzkey"))]
use {ark_circom::read_zkey, std::io::Cursor};

#[cfg(feature = "arkzkey")]
pub const ARKZKEY_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln_final.arkzkey");
#[cfg(feature = "arkzkey")]
pub const ARKZKEY_BYTES_UNCOMPR: &[u8] =
    include_bytes!("../resources/tree_height_20/rln_final_uncompr.arkzkey");

pub const ZKEY_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln_final.zkey");
pub const VK_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/verification_key.arkvkey");
const WASM_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln.wasm");

#[cfg(not(target_arch = "wasm32"))]
lazy_static! {
    #[cfg(not(target_arch = "wasm32"))]
    static ref ZKEY: (ProvingKey<Curve>, ConstraintMatrices<Fr>) = {
        cfg_if! {
                if #[cfg(feature = "arkzkey")] {
                    read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES_UNCOMPR).expect("Failed to read arkzkey")
                } else {
                    let mut reader = Cursor::new(ZKEY_BYTES);
                    read_zkey(&mut reader).expect("Failed to read zkey")
                }
        }
    };

    #[cfg(not(target_arch = "wasm32"))]
    static ref VK: VerifyingKey<Curve> = vk_from_ark_serialized(VK_BYTES).expect("Failed to read vk");

    #[cfg(not(target_arch = "wasm32"))]
    static ref WITNESS_CALCULATOR: Arc<Mutex<WitnessCalculator>> = {
        circom_from_raw(WASM_BYTES).expect("Failed to create witness calculator")
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
        () => read_arkzkey_from_bytes(zkey_data)?,
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

// Loads the verification key from a bytes vector
pub fn vk_from_raw(vk_data: &[u8], zkey_data: &[u8]) -> Result<VerifyingKey<Curve>> {
    if !vk_data.is_empty() {
        return vk_from_ark_serialized(vk_data);
    }

    if !zkey_data.is_empty() {
        let (proving_key, _matrices) = zkey_from_raw(zkey_data)?;
        return Ok(proving_key.vk);
    }

    Err(Report::msg("No proving/verification key found!"))
}

// Loads the verification key
#[cfg(not(target_arch = "wasm32"))]
pub fn vk_from_folder() -> &'static VerifyingKey<Curve> {
    &VK
}

// Initializes the witness calculator using a bytes vector
#[cfg(not(target_arch = "wasm32"))]
pub fn circom_from_raw(wasm_buffer: &[u8]) -> Result<Arc<Mutex<WitnessCalculator>>> {
    let module = Module::new(&Store::default(), wasm_buffer)?;
    let result = WitnessCalculator::from_module(module)?;
    Ok(Arc::new(Mutex::new(result)))
}

// Initializes the witness calculator
#[cfg(not(target_arch = "wasm32"))]
pub fn circom_from_folder() -> &'static Arc<Mutex<WitnessCalculator>> {
    &WITNESS_CALCULATOR
}

// Computes the verification key from a bytes vector containing pre-processed ark-serialized verification key
// uncompressed, unchecked
pub fn vk_from_ark_serialized(data: &[u8]) -> Result<VerifyingKey<Curve>> {
    let vk = VerifyingKey::<Curve>::deserialize_uncompressed_unchecked(data)?;
    Ok(vk)
}

// Checks verification key to be correct with respect to proving key
#[cfg(not(target_arch = "wasm32"))]
pub fn check_vk_from_zkey(verifying_key: VerifyingKey<Curve>) -> Result<()> {
    let (proving_key, _matrices) = zkey_from_folder();
    if proving_key.vk == verifying_key {
        Ok(())
    } else {
        Err(Report::msg("verifying_keys are not equal"))
    }
}

////////////////////////////////////////////////////////
// Functions from [arkz-key](https://github.com/zkmopro/ark-zkey/blob/main/src/lib.rs#L106)
// without print and allow to choose between compressed and uncompressed arkzkey
////////////////////////////////////////////////////////
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

#[cfg(feature = "arkzkey")]
pub fn read_arkzkey_from_bytes_compressed(
    arkzkey_data: &[u8],
) -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> {
    if arkzkey_data.is_empty() {
        return Err(Report::msg("No proving key found!"));
    }

    let mut cursor = std::io::Cursor::new(arkzkey_data);

    let serialized_proving_key =
        SerializableProvingKey::deserialize_compressed_unchecked(&mut cursor)
            .wrap_err("Failed to deserialize proving key")?;

    let serialized_constraint_matrices =
        SerializableConstraintMatrices::deserialize_compressed_unchecked(&mut cursor)
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
