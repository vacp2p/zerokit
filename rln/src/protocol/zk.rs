use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};

use crate::{
    circuit::{
        iden3calc::{calc_witness, calc_witness_partial},
        qap::CircomReduction,
        ArkGroth16BackendWithGraph, ArkGroth16BackendWithoutGraph, Fr, PartialProof, Proof, Zkey,
    },
    error::{ProtocolError, RLNError},
    partial_proof::{Groth16Partial, PartialAssignment},
    prelude::{CanonicalDeserializeBE, CanonicalSerializeBE, RLNPartialWitnessInputV3},
    protocol::{proof::RLNProofValuesV3, witness::RLNWitnessInputV3},
    utils::IdSecret,
};

pub trait RLNZkProof {
    type Values: RecoverSecret
        + CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Proof: CanonicalSerialize + CanonicalDeserialize;
    type Error;

    fn generate_proof_from_calculated_witness(
        &self,
        calculated_witness: &[Fr],
    ) -> Result<Self::Proof, Self::Error>;
    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error>;
}

pub trait RLNZkProofWithGraph: RLNZkProof {
    type Witness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;

    fn calculate_witness(&self, witness: &Self::Witness) -> Result<Vec<Fr>, Self::Error>;

    fn generate_proof_from_witness(
        &self,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, Self::Error>;
}

pub trait RecoverSecret<Rhs = Self> {
    type Error;

    fn recover_secret(&self, other: &Rhs) -> Result<IdSecret, Self::Error>;
}

pub trait RLNPartialZkProof: RLNZkProofWithGraph {
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

impl RLNZkProof for ArkGroth16BackendWithGraph {
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNError;

    fn generate_proof_from_calculated_witness(
        &self,
        calculated_witness: &[Fr],
    ) -> Result<Self::Proof, Self::Error> {
        prove(&self.zkey, calculated_witness)
    }

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error> {
        verify(&self.zkey, proof, values)
    }
}

impl RLNZkProofWithGraph for ArkGroth16BackendWithGraph {
    type Witness = RLNWitnessInputV3;

    fn calculate_witness(&self, witness: &Self::Witness) -> Result<Vec<Fr>, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let inputs = witness
            .to_circuit_inputs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v));

        Ok(calc_witness(inputs, &self.graph).map_err(ProtocolError::from)?)
    }

    fn generate_proof_from_witness(
        &self,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, Self::Error> {
        let calculated_witness = self.calculate_witness(witness)?;
        self.generate_proof_from_calculated_witness(&calculated_witness)
    }
}

impl RLNZkProof for ArkGroth16BackendWithoutGraph {
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNError;

    fn generate_proof_from_calculated_witness(
        &self,
        calculated_witness: &[Fr],
    ) -> Result<Self::Proof, Self::Error> {
        prove(&self.zkey, calculated_witness)
    }

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error> {
        verify(&self.zkey, proof, values)
    }
}

impl RLNPartialZkProof for ArkGroth16BackendWithGraph {
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
        let calculated_witness = self.calculate_witness(&witness)?;

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);

        let proof = Groth16Partial::<_, CircomReduction>::finish_proof_with_matrices(
            &self.zkey.0,
            &partial,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            &calculated_witness,
        )?;
        Ok(proof)
    }
}

fn prove(zkey: &Zkey, calculated_witness: &[Fr]) -> Result<Proof, RLNError> {
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        calculated_witness,
    )
    .map_err(ProtocolError::from)
    .map_err(Into::into)
}

fn verify(zkey: &Zkey, proof: &Proof, values: &RLNProofValuesV3) -> Result<bool, RLNError> {
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
    let pvk = prepare_verifying_key(&zkey.0.vk);
    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &public_inputs)
        .map_err(ProtocolError::from)?;
    Ok(verified)
}
