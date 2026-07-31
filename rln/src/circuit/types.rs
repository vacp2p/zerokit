use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_groth16::{
    Proof as ArkProof, ProvingKey as ArkProvingKey, VerifyingKey as ArkVerifyingKey,
};
use ark_relations::r1cs::ConstraintMatrices;

use crate::partial_proof::PartialProof as ArkPartialProof;

/// Default maximum number of message-id slots supported by the multi circuit.
pub const DEFAULT_MAX_OUT: usize = 4;
/// Default Merkle tree depth.
pub const DEFAULT_TREE_DEPTH: usize = 20;

// The following types define the pairing friendly elliptic curve, the underlying finite fields
// and groups default to this module.

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

/// Partial Groth16 proof for the BN254 curve.
pub type PartialProof = ArkPartialProof<Curve>;

/// Proving key for the Groth16 proof system.
pub type ProvingKey = ArkProvingKey<Curve>;

/// Combining the proving key and constraint matrices.
pub type Zkey = (ArkProvingKey<Curve>, ConstraintMatrices<Fr>);

/// Verifying key for the Groth16 proof system.
pub type VerifyingKey = ArkVerifyingKey<Curve>;
