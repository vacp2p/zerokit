use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};

use crate::{
    circuit::{
        iden3calc::{calc_witness, calc_witness_partial},
        qap::CircomReduction,
        ArkGroth16Backend, Fr, PartialProof, Proof,
    },
    error::{ProtocolError, RLNError},
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
    type Error;

    fn generate_proof(&self, witness: &Self::Witness) -> Result<Self::Proof, Self::Error>;
    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error>;
}

pub trait RecoverSecret<Rhs = Self> {
    type Error;

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
        witness: Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error>;

    fn finish_proof(
        &self,
        partial: Self::PartialProof,
        witness: Self::Witness,
    ) -> Result<Self::Proof, Self::Error>;
}

impl RLNZkProof for ArkGroth16Backend {
    type Witness = RLNWitnessInputV3;
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNError;

    fn generate_proof(&self, witness: &Self::Witness) -> Result<Self::Proof, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let inputs = witness
            .to_circuit_inputs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v));

        let calculated_witness = calc_witness(inputs, &self.graph).map_err(ProtocolError::from)?;

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.zkey.0,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            &calculated_witness,
        )
        .map_err(ProtocolError::from)
        .map_err(Into::into)
    }

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error> {
        let public_inputs: Vec<Fr> = match values {
            RLNProofValuesV3::Single(v) => {
                vec![v.y, v.root, v.nullifier, v.x, v.external_nullifier]
            }
            RLNProofValuesV3::Multi(v) => {
                let mut inputs = Vec::with_capacity(3 * v.ys.len() + 3);
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
        Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &public_inputs)
            .map_err(ProtocolError::from)
            .map_err(Into::into)
    }
}

impl RLNPartialZkProof for ArkGroth16Backend {
    type PartialWitness = RLNPartialWitnessInputV3;
    type PartialProof = PartialProof;

    fn generate_partial_proof(
        &self,
        witness: Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let inputs = witness
            .to_circuit_inputs(self.graph.max_out)
            .into_iter()
            .map(|(k, v)| (k.to_string(), v));

        let full_assignment =
            calc_witness_partial(inputs, &self.graph).map_err(ProtocolError::from)?;

        let partial_assignment = PartialAssignment::new(full_assignment[1..].to_vec());
        let partial_proof =
            Groth16Partial::<_, CircomReduction>::prove_partial(&self.zkey.0, &partial_assignment)?;
        Ok(partial_proof)
    }

    fn finish_proof(
        &self,
        partial: Self::PartialProof,
        witness: Self::Witness,
    ) -> Result<Self::Proof, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let inputs = witness
            .to_circuit_inputs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v));

        let calculated_witness = calc_witness(inputs, &self.graph).map_err(ProtocolError::from)?;

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        Groth16Partial::<_, CircomReduction>::finish_proof_with_matrices(
            &self.zkey.0,
            &partial,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            &calculated_witness,
        )
        .map_err(Into::into)
    }
}
