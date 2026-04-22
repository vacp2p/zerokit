// This crate provides interfaces for the zero-knowledge circuit and keys

pub(crate) mod error;
pub(crate) mod iden3calc;
pub(crate) mod qap;

use std::io::{Read, Write};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::LazyLock;

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_groth16::{
    Proof as ArkProof, ProvingKey as ArkProvingKey, VerifyingKey as ArkVerifyingKey,
};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};

#[cfg(not(target_arch = "wasm32"))]
use self::error::GraphReadError;
use self::error::ZKeyReadError;
#[cfg(not(target_arch = "wasm32"))]
use crate::circuit::iden3calc::{
    graph::Node, storage::deserialize_witnesscalc_graph, InputSignalsInfo,
};
use crate::{
    error::ProtocolError,
    partial_proof::PartialProof as ArkPartialProof,
    prelude::{CanonicalDeserializeBE, CanonicalSerializeBE},
    utils::{
        bytes_be_to_fq, bytes_be_to_vec_bool, fq_to_bytes_be, vec_bool_to_bytes_be, FQ_BYTE_SIZE,
        VEC_LEN_BYTE_SIZE,
    },
};

#[cfg(not(target_arch = "wasm32"))]
const GRAPH_BYTES_SINGLE_V1: &[u8] = include_bytes!("../../resources/tree_depth_20/graph.bin");

#[cfg(not(target_arch = "wasm32"))]
const ARKZKEY_BYTES_SINGLE_V1: &[u8] =
    include_bytes!("../../resources/tree_depth_20/rln_final.arkzkey");

#[cfg(not(target_arch = "wasm32"))]
const GRAPH_BYTES_MULTI_V1: &[u8] =
    include_bytes!("../../resources/tree_depth_20/multi_message_id/max_out_4/graph.bin");

#[cfg(not(target_arch = "wasm32"))]
const ARKZKEY_BYTES_MULTI_V1: &[u8] =
    include_bytes!("../../resources/tree_depth_20/multi_message_id/max_out_4/rln_final.arkzkey");

#[cfg(not(target_arch = "wasm32"))]
static ARKZKEY_SINGLE_V1: LazyLock<Zkey> = LazyLock::new(|| {
    read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES_SINGLE_V1)
        .expect("Default SingleV1 zkey must be valid")
});

#[cfg(not(target_arch = "wasm32"))]
static ARKZKEY_MULTI_V1: LazyLock<Zkey> = LazyLock::new(|| {
    read_arkzkey_from_bytes_uncompressed(ARKZKEY_BYTES_MULTI_V1)
        .expect("Default MultiV1 zkey must be valid")
});

#[cfg(not(target_arch = "wasm32"))]
static GRAPH_SINGLE_V1: LazyLock<Graph> = LazyLock::new(|| {
    graph_from_raw(GRAPH_BYTES_SINGLE_V1, Some(DEFAULT_TREE_DEPTH), None)
        .expect("Default SingleV1 graph must be valid")
});

#[cfg(not(target_arch = "wasm32"))]
static GRAPH_MULTI_V1: LazyLock<Graph> = LazyLock::new(|| {
    graph_from_raw(
        GRAPH_BYTES_MULTI_V1,
        Some(DEFAULT_TREE_DEPTH),
        Some(DEFAULT_MAX_OUT),
    )
    .expect("Default MultiV1 graph must be valid")
});

pub const DEFAULT_MAX_OUT: usize = 4;
pub const DEFAULT_TREE_DEPTH: usize = 20;
pub const COMPRESS_PROOF_SIZE: usize = 128;
pub const UNCOMPRESSED_PROOF_SIZE: usize = 256;

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

impl CanonicalSerializeBE for Proof {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&fq_to_bytes_be(&self.a.x))?;
        writer.write_all(&fq_to_bytes_be(&self.a.y))?;
        writer.write_all(&fq_to_bytes_be(&self.b.x.c1))?;
        writer.write_all(&fq_to_bytes_be(&self.b.x.c0))?;
        writer.write_all(&fq_to_bytes_be(&self.b.y.c1))?;
        writer.write_all(&fq_to_bytes_be(&self.b.y.c0))?;
        writer.write_all(&fq_to_bytes_be(&self.c.x))?;
        writer.write_all(&fq_to_bytes_be(&self.c.y))?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        UNCOMPRESSED_PROOF_SIZE
    }
}

impl CanonicalDeserializeBE for Proof {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut buf = [0u8; FQ_BYTE_SIZE];

        reader.read_exact(&mut buf)?;
        let (ax, _) = bytes_be_to_fq(&buf)?;
        reader.read_exact(&mut buf)?;
        let (ay, _) = bytes_be_to_fq(&buf)?;
        let a = G1Affine {
            x: ax,
            y: ay,
            infinity: false,
        };
        a.check()?;

        reader.read_exact(&mut buf)?;
        let (bx_c1, _) = bytes_be_to_fq(&buf)?;
        reader.read_exact(&mut buf)?;
        let (bx_c0, _) = bytes_be_to_fq(&buf)?;
        reader.read_exact(&mut buf)?;
        let (by_c1, _) = bytes_be_to_fq(&buf)?;
        reader.read_exact(&mut buf)?;
        let (by_c0, _) = bytes_be_to_fq(&buf)?;
        let b = G2Affine {
            x: Fq2::new(bx_c0, bx_c1),
            y: Fq2::new(by_c0, by_c1),
            infinity: false,
        };
        b.check()?;

        reader.read_exact(&mut buf)?;
        let (cx, _) = bytes_be_to_fq(&buf)?;
        reader.read_exact(&mut buf)?;
        let (cy, _) = bytes_be_to_fq(&buf)?;
        let c = G1Affine {
            x: cx,
            y: cy,
            infinity: false,
        };
        c.check()?;

        Ok(Proof { a, b, c })
    }
}

/// Partial Groth16 proof for the BN254 curve.
pub type PartialProof = ArkPartialProof<Curve>;

impl CanonicalSerializeBE for PartialProof {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&vec_bool_to_bytes_be(&self.mask))?;
        let a = self.partial_pi_a.into_affine();
        writer.write_all(&fq_to_bytes_be(&a.x))?;
        writer.write_all(&fq_to_bytes_be(&a.y))?;
        let rho = self.partial_rho.into_affine();
        writer.write_all(&fq_to_bytes_be(&rho.x))?;
        writer.write_all(&fq_to_bytes_be(&rho.y))?;
        let b = self.partial_pi_b.into_affine();
        writer.write_all(&fq_to_bytes_be(&b.x.c1))?;
        writer.write_all(&fq_to_bytes_be(&b.x.c0))?;
        writer.write_all(&fq_to_bytes_be(&b.y.c1))?;
        writer.write_all(&fq_to_bytes_be(&b.y.c0))?;
        let c = self.partial_pi_c.into_affine();
        writer.write_all(&fq_to_bytes_be(&c.x))?;
        writer.write_all(&fq_to_bytes_be(&c.y))?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        VEC_LEN_BYTE_SIZE + self.mask.len() + FQ_BYTE_SIZE * 10
    }
}

impl CanonicalDeserializeBE for PartialProof {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let mut read = 0;

        let (mask, el_size) = bytes_be_to_vec_bool(&bytes[read..])?;
        read += el_size;

        let (ax, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let (ay, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let a_affine = G1Affine {
            x: ax,
            y: ay,
            infinity: false,
        };
        a_affine.check()?;

        let (rhox, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let (rhoy, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let rho_affine = G1Affine {
            x: rhox,
            y: rhoy,
            infinity: false,
        };
        rho_affine.check()?;

        let (bx_c1, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let (bx_c0, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let (by_c1, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let (by_c0, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let b_affine = G2Affine {
            x: Fq2::new(bx_c0, bx_c1),
            y: Fq2::new(by_c0, by_c1),
            infinity: false,
        };
        b_affine.check()?;

        let (cx, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let (cy, el_size) = bytes_be_to_fq(&bytes[read..])?;
        read += el_size;
        let c_affine = G1Affine {
            x: cx,
            y: cy,
            infinity: false,
        };
        c_affine.check()?;

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }
        Ok(PartialProof {
            mask,
            partial_pi_a: a_affine.into(),
            partial_rho: rho_affine.into(),
            partial_pi_b: b_affine.into(),
            partial_pi_c: c_affine.into(),
        })
    }
}

/// Proving key for the Groth16 proof system.
pub type ProvingKey = ArkProvingKey<Curve>;

/// Combining the proving key and constraint matrices.
pub type Zkey = (ArkProvingKey<Curve>, ConstraintMatrices<Fr>);

/// Verifying key for the Groth16 proof system.
pub type VerifyingKey = ArkVerifyingKey<Curve>;

/// Parsed witness calculator graph.
///
/// Contains the deserialized computation graph used for witness calculation.
/// Parsing this once and reusing it avoids repeated deserialization overhead.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct Graph {
    pub(crate) nodes: Vec<Node>,
    pub(crate) signals: Vec<usize>,
    pub(crate) input_mapping: InputSignalsInfo,
    pub(crate) tree_depth: usize,
    pub(crate) max_out: usize,
}

/// Loads the zkey from raw bytes
pub fn zkey_from_raw(zkey_data: &[u8]) -> Result<Zkey, ZKeyReadError> {
    if zkey_data.is_empty() {
        return Err(ZKeyReadError::EmptyBytes);
    }

    let proving_key_and_matrices = read_arkzkey_from_bytes_uncompressed(zkey_data)?;

    Ok(proving_key_and_matrices)
}

/// Parses the witness calculator graph from raw bytes
#[cfg(not(target_arch = "wasm32"))]
pub fn graph_from_raw(
    graph_data: &[u8],
    expected_tree_depth: Option<usize>,
    expected_max_out: Option<usize>,
) -> Result<Graph, GraphReadError> {
    if graph_data.is_empty() {
        return Err(GraphReadError::EmptyBytes);
    }

    let (nodes, signals, input_mapping) =
        deserialize_witnesscalc_graph(std::io::Cursor::new(graph_data))
            .map_err(GraphReadError::GraphDeserialization)?;

    let tree_depth = {
        let depth = input_mapping
            .get("pathElements")
            .map(|(_, len)| *len)
            .unwrap_or_default();

        if let Some(expected) = expected_tree_depth {
            if expected != depth {
                return Err(GraphReadError::TreeDepthMismatch {
                    expected,
                    actual: depth,
                });
            }
        }

        depth
    };

    let max_out = match input_mapping.get("messageId") {
        Some((_, count)) => {
            if let Some(expected) = expected_max_out {
                if expected != *count {
                    return Err(GraphReadError::MaxOutMismatch {
                        expected,
                        actual: *count,
                    });
                }
            }
            *count
        }
        None => 1, // single-message-id graph: max_out = 1
    };

    Ok(Graph {
        nodes,
        signals,
        input_mapping,
        tree_depth,
        max_out,
    })
}

// Loads default SingleV1 zkey
#[cfg(not(target_arch = "wasm32"))]
pub fn zkey_single_v1() -> &'static Zkey {
    &ARKZKEY_SINGLE_V1
}

// Loads default MultiV1 zkey
#[cfg(not(target_arch = "wasm32"))]
pub fn zkey_multi_v1() -> &'static Zkey {
    &ARKZKEY_MULTI_V1
}

// Loads default SingleV1 parsed graph
#[cfg(not(target_arch = "wasm32"))]
pub fn graph_single_v1() -> &'static Graph {
    &GRAPH_SINGLE_V1
}

// Loads default MultiV1 parsed graph
#[cfg(not(target_arch = "wasm32"))]
pub fn graph_multi_v1() -> &'static Graph {
    &GRAPH_MULTI_V1
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

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct ArkGroth16Backend {
    pub(crate) _zkey: Zkey,
    pub(crate) _graph: Graph,
}

#[cfg(not(target_arch = "wasm32"))]
impl ArkGroth16Backend {
    pub fn new(zkey: Zkey, graph: Graph) -> Self {
        Self {
            _zkey: zkey,
            _graph: graph,
        }
    }
}

#[cfg(test)]
mod test {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    use super::*;
    use crate::prelude::{
        generate_partial_zk_proof, generate_zk_proof, keygen, RLNPartialWitnessInput,
        RLNWitnessInput,
    };

    #[test]
    fn test_empty_zkey_and_graph() {
        let err = zkey_from_raw(&[]).unwrap_err();
        assert!(matches!(err, ZKeyReadError::EmptyBytes));

        let err = graph_from_raw(&[], None, None).err().unwrap();
        assert!(matches!(err, GraphReadError::EmptyBytes));

        let err = read_arkzkey_from_bytes_uncompressed(&[]).unwrap_err();
        assert!(matches!(err, ZKeyReadError::EmptyBytes));
    }

    #[test]
    fn test_tree_depth_mismatch() {
        let err = graph_from_raw(GRAPH_BYTES_SINGLE_V1, Some(DEFAULT_TREE_DEPTH + 1), None)
            .err()
            .unwrap();
        assert!(matches!(err, GraphReadError::TreeDepthMismatch { .. }));
    }

    #[test]
    fn test_max_out_mismatch() {
        let err = graph_from_raw(
            GRAPH_BYTES_MULTI_V1,
            Some(DEFAULT_TREE_DEPTH),
            Some(DEFAULT_MAX_OUT + 1),
        )
        .err()
        .unwrap();
        assert!(matches!(err, GraphReadError::MaxOutMismatch { .. }));
    }

    #[test]
    fn test_proof_le_compressed_roundtrip() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0); DEFAULT_TREE_DEPTH];
        let identity_path_index = vec![0; DEFAULT_TREE_DEPTH];
        let witness = RLNWitnessInput::new_single(
            identity_secret,
            Fr::from(100),
            Fr::from(1),
            path_elements,
            identity_path_index,
            Fr::from(1),
            Fr::from(100),
        )
        .unwrap();
        let proof = generate_zk_proof(&ARKZKEY_SINGLE_V1, &witness, &GRAPH_SINGLE_V1).unwrap();
        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        let deser = Proof::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(proof, deser);
        assert_eq!(proof.compressed_size(), buf.len());
    }

    #[test]
    fn test_proof_be_roundtrip() {
        use crate::prelude::{CanonicalDeserializeBE, CanonicalSerializeBE};

        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0); DEFAULT_TREE_DEPTH];
        let identity_path_index = vec![0; DEFAULT_TREE_DEPTH];
        let witness = RLNWitnessInput::new_single(
            identity_secret,
            Fr::from(100),
            Fr::from(1),
            path_elements,
            identity_path_index,
            Fr::from(1),
            Fr::from(100),
        )
        .unwrap();
        let proof = generate_zk_proof(&ARKZKEY_SINGLE_V1, &witness, &GRAPH_SINGLE_V1).unwrap();
        let mut buf = Vec::new();
        CanonicalSerializeBE::serialize(&proof, &mut buf).unwrap();
        assert_eq!(buf.len(), UNCOMPRESSED_PROOF_SIZE);
        let deser = Proof::deserialize(buf.as_slice()).unwrap();
        assert_eq!(proof, deser);
        assert_eq!(
            CanonicalSerializeBE::serialized_size(&proof),
            UNCOMPRESSED_PROOF_SIZE
        );
    }

    #[test]
    fn test_partial_proof_le_compressed_roundtrip() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0); DEFAULT_TREE_DEPTH];
        let identity_path_index = vec![0; DEFAULT_TREE_DEPTH];
        let partial_witness = RLNPartialWitnessInput::new(
            identity_secret,
            Fr::from(100),
            path_elements,
            identity_path_index,
        )
        .unwrap();
        let partial =
            generate_partial_zk_proof(&ARKZKEY_SINGLE_V1, &partial_witness, &GRAPH_SINGLE_V1)
                .unwrap();
        let mut buf = Vec::new();
        partial.serialize_compressed(&mut buf).unwrap();
        let deser = PartialProof::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(partial, deser);
        assert_eq!(partial.compressed_size(), buf.len());
    }

    #[test]
    fn test_partial_proof_be_roundtrip() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0); DEFAULT_TREE_DEPTH];
        let identity_path_index = vec![0; DEFAULT_TREE_DEPTH];
        let partial_witness = RLNPartialWitnessInput::new(
            identity_secret,
            Fr::from(100),
            path_elements,
            identity_path_index,
        )
        .unwrap();
        let partial =
            generate_partial_zk_proof(&ARKZKEY_SINGLE_V1, &partial_witness, &GRAPH_SINGLE_V1)
                .unwrap();
        let mut buf = Vec::new();
        CanonicalSerializeBE::serialize(&partial, &mut buf).unwrap();
        let deser = PartialProof::deserialize(buf.as_slice()).unwrap();
        assert_eq!(partial, deser);
        assert_eq!(CanonicalSerializeBE::serialized_size(&partial), buf.len());
    }
}
