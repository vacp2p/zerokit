use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use zerokit_utils::hasher::ZerokitHasher;

use crate::{
    circuit::{qap::CircomReduction, ArkGroth16Backend, Fr, PartialProof, Proof, SecretFr},
    error::{GenerateProofError, VerifyProofError},
    partial_proof::{Groth16Partial, PartialAssignment},
    protocol::{
        proof::RLNProofValues, witness::RLNWitnessInput, CanonicalDeserializeBE,
        CanonicalSerializeBE, RLNPartialWitnessInput,
    },
};

/// A zkSNARK proof backend for RLN: generates and verifies proofs and their public values.
pub trait RLNZkProof {
    /// The protocol hash used to derive proof values.
    type Hasher: ZerokitHasher<Scalar = Fr>;
    /// The witness type consumed by proof generation.
    type Witness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    /// The public proof values type produced alongside a proof.
    type Values: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE
        + RecoverSecret;
    /// The zkSNARK proof type.
    type Proof: CanonicalSerialize + CanonicalDeserialize;
    /// The error type returned by [`Self::generate_proof`].
    type GenerateProofError: std::error::Error;
    /// The error type returned by [`Self::verify`].
    type VerifyProofError: std::error::Error;

    /// Generates a proof and its public values from a `witness`.
    fn generate_proof(
        &self,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::GenerateProofError>;
    /// Verifies a `proof` against its public `values`.
    fn verify(
        &self,
        proof: &Self::Proof,
        values: &Self::Values,
    ) -> Result<bool, Self::VerifyProofError>;
}

/// Recovers an identity secret from two sets of proof values that reused an external nullifier.
pub trait RecoverSecret<Rhs = Self> {
    /// The error type returned by [`Self::recover_secret`].
    type Error: std::error::Error;

    /// Recovers the identity secret from `self` and `other`, or returns an error if they do not
    /// yield a matching nullifier (no slashing possible).
    fn recover_secret(&self, other: &Rhs) -> Result<SecretFr, Self::Error>;
}

/// Two-step proof generation on top of [`RLNZkProof`]: a partial proof from the known inputs,
/// finished later with the full witness.
pub trait RLNPartialZkProof: RLNZkProof {
    /// The partial witness type consumed by [`Self::generate_partial_proof`].
    type PartialWitness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    /// The partial proof type produced by [`Self::generate_partial_proof`].
    type PartialProof: CanonicalSerialize + CanonicalDeserialize;
    /// The error type returned by [`Self::generate_partial_proof`].
    type GeneratePartialProofError: std::error::Error;
    /// The error type returned by [`Self::finish_proof`].
    type FinishProofError: std::error::Error;

    /// Generates a partial proof from partial `witness` inputs.
    fn generate_partial_proof(
        &self,
        witness: &Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::GeneratePartialProofError>;

    /// Completes proof generation from a `partial` proof and the full `witness`.
    fn finish_proof(
        &self,
        partial: &Self::PartialProof,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::FinishProofError>;
}

impl<H> RLNZkProof for ArkGroth16Backend<H>
where
    H: ZerokitHasher<Scalar = Fr>,
{
    type Hasher = H;
    type Witness = RLNWitnessInput;
    type Values = RLNProofValues;
    type Proof = Proof;
    type GenerateProofError = GenerateProofError;
    type VerifyProofError = VerifyProofError;

    fn generate_proof(
        &self,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::GenerateProofError> {
        witness.validate_against_graph(&self.graph)?;
        let values = RLNProofValues::from_witness::<Self::Hasher>(witness);

        let full_assignment = witness.calc_witness(&self.graph)?;

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.zkey.0,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            &full_assignment,
        )?;

        Ok((proof, values))
    }

    fn verify(
        &self,
        proof: &Self::Proof,
        values: &Self::Values,
    ) -> Result<bool, Self::VerifyProofError> {
        let public_inputs: Vec<Fr> = match values {
            RLNProofValues::Single(v) => {
                vec![v.y, v.root, v.nullifier, v.x, v.external_nullifier]
            }
            RLNProofValues::Multi(v) => {
                let mut inputs =
                    Vec::with_capacity(v.ys.len() + v.nullifiers.len() + v.selector_used.len() + 3);
                inputs.extend_from_slice(&v.ys);
                inputs.push(v.root);
                inputs.extend_from_slice(&v.nullifiers);
                inputs.push(v.x);
                inputs.push(v.external_nullifier);
                for &used in &v.selector_used {
                    inputs.push(Fr::from(used));
                }
                inputs
            }
        };
        let verified =
            Groth16::<_, CircomReduction>::verify_proof(&self.pvk, proof, &public_inputs)?;

        Ok(verified)
    }
}

impl<H> RLNPartialZkProof for ArkGroth16Backend<H>
where
    H: ZerokitHasher<Scalar = Fr>,
{
    type PartialWitness = RLNPartialWitnessInput;
    type PartialProof = PartialProof;
    type GeneratePartialProofError = GenerateProofError;
    type FinishProofError = GenerateProofError;

    fn generate_partial_proof(
        &self,
        witness: &Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::GeneratePartialProofError> {
        witness.validate_against_graph(&self.graph)?;

        let mut partial_assignment = witness.calc_witness_partial(&self.graph)?;
        partial_assignment.drain(..1);

        let partial_proof = Groth16Partial::<_, CircomReduction>::prove_partial(
            &self.zkey.0,
            &PartialAssignment::new(partial_assignment),
        )?;

        Ok(partial_proof)
    }

    fn finish_proof(
        &self,
        partial: &Self::PartialProof,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::FinishProofError> {
        witness.validate_against_graph(&self.graph)?;
        let values = RLNProofValues::from_witness::<Self::Hasher>(witness);

        let full_assignment = witness.calc_witness(&self.graph)?;

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);

        let full_proof = Groth16Partial::<_, CircomReduction>::finish_proof_with_matrices(
            &self.zkey.0,
            partial,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            &full_assignment,
        )?;

        Ok((full_proof, values))
    }
}
