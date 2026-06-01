use std::error::Error;

use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};

use crate::{
    circuit::{
        qap::CircomReduction, ArkGroth16Backend, CalcWitness, CalcWitnessPartial, Fr, PartialProof,
        Proof,
    },
    error::RLNErrorV3,
    partial_proof::{Groth16Partial, PartialAssignment},
    prelude::{CanonicalDeserializeBE, CanonicalSerializeBE, RLNPartialWitnessInputV3},
    protocol::{proof::RLNProofValuesV3, witness::RLNWitnessInputV3},
    utils::IdSecret,
};

pub trait RLNZkProof {
    type Witness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Values: RecoverSecret
        + CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Proof: CanonicalSerialize + CanonicalDeserialize;
    type Error: Error;

    fn generate_proof(
        &self,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error>;
    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error>;
}

pub trait RecoverSecret<Rhs = Self> {
    type Error: Error;

    fn recover_secret(&self, other: &Rhs) -> Result<IdSecret, Self::Error>;
}

pub trait RLNPartialZkProof: RLNZkProof {
    type PartialWitness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type PartialProof: CanonicalSerialize + CanonicalDeserialize;

    fn generate_partial_proof(
        &self,
        witness: &Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error>;

    fn finish_proof(
        &self,
        partial: &Self::PartialProof,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error>;
}

impl RLNZkProof for ArkGroth16Backend {
    type Witness = RLNWitnessInputV3;
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNErrorV3;

    fn generate_proof(
        &self,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error> {
        witness.validate_against_graph(&self.graph)?;
        let values = RLNProofValuesV3::from(witness);

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

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error> {
        let public_inputs: Vec<Fr> = match values {
            RLNProofValuesV3::Single(v) => {
                vec![v.y, v.root, v.nullifier, v.x, v.external_nullifier]
            }
            RLNProofValuesV3::Multi(v) => {
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
        let pvk = prepare_verifying_key(&self.zkey.0.vk);
        let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &public_inputs)?;

        Ok(verified)
    }
}

impl RLNPartialZkProof for ArkGroth16Backend {
    type PartialWitness = RLNPartialWitnessInputV3;
    type PartialProof = PartialProof;

    fn generate_partial_proof(
        &self,
        witness: &Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let partial_assignment = witness.calc_witness_partial(&self.graph)?;

        let partial_proof = Groth16Partial::<_, CircomReduction>::prove_partial(
            &self.zkey.0,
            &PartialAssignment::new(partial_assignment[1..].to_vec()),
        )?;

        Ok(partial_proof)
    }

    fn finish_proof(
        &self,
        partial: &Self::PartialProof,
        witness: &Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error> {
        witness.validate_against_graph(&self.graph)?;
        let values = RLNProofValuesV3::from(witness);

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
