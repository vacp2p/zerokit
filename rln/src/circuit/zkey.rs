#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, LazyLock};

use ark_ff::Field;
use ark_groth16::ProvingKey as ArkProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::{error::ZKeyReadError, Curve, Fr, ProvingKey, Zkey};

#[cfg(not(target_arch = "wasm32"))]
const ARKZKEY_BYTES_SINGLE: &[u8] =
    include_bytes!("../../resources/tree_depth_20/rln_final.arkzkey");

#[cfg(not(target_arch = "wasm32"))]
const ARKZKEY_BYTES_MULTI: &[u8] =
    include_bytes!("../../resources/tree_depth_20/multi_message_id/max_out_4/rln_final.arkzkey");

#[cfg(not(target_arch = "wasm32"))]
static ARKZKEY_SINGLE: LazyLock<Arc<Zkey>> = LazyLock::new(|| {
    Arc::new(
        read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES_SINGLE)
            .expect("Default Single zkey must be valid"),
    )
});

#[cfg(not(target_arch = "wasm32"))]
static ARKZKEY_MULTI: LazyLock<Arc<Zkey>> = LazyLock::new(|| {
    Arc::new(
        read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES_MULTI)
            .expect("Default Multi zkey must be valid"),
    )
});

/// Loads the zkey from raw bytes
pub fn zkey_from_raw(zkey_data: &[u8]) -> Result<Zkey, ZKeyReadError> {
    if zkey_data.is_empty() {
        return Err(ZKeyReadError::EmptyBytes);
    }

    let proving_key_and_matrices = read_arkzkey_from_bytes_uncompressed(zkey_data)?;

    Ok(proving_key_and_matrices)
}

/// Loads default Single zkey
#[cfg(not(target_arch = "wasm32"))]
pub fn default_zkey_single() -> &'static Arc<Zkey> {
    &ARKZKEY_SINGLE
}

/// Loads default Multi zkey
#[cfg(not(target_arch = "wasm32"))]
pub fn default_zkey_multi() -> &'static Arc<Zkey> {
    &ARKZKEY_MULTI
}

// The following functions and structs are based on code from ark-zkey:
// https://github.com/zkmopro/ark-zkey/blob/main/src/lib.rs#L106

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct SerializableProvingKey(ArkProvingKey<Curve>);

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
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

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty_zkey() {
        let err = zkey_from_raw(&[]).unwrap_err();
        assert!(matches!(err, ZKeyReadError::EmptyBytes));

        let err = read_arkzkey_from_bytes_uncompressed(&[]).unwrap_err();
        assert!(matches!(err, ZKeyReadError::EmptyBytes));
    }
}
