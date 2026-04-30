use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    circuit::Fr,
    prelude::{CanonicalDeserializeBE, CanonicalSerializeBE},
};
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    circuit::{ArkGroth16Backend, PartialProof, Proof},
    error::RLNError,
    prelude::RLNPartialWitnessInputV3,
    protocol::{RLNProofValuesV3, RLNWitnessInputV3},
};

pub trait RLNZkProof {
    type Witness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Values: RecoverSecret
        + TryFrom<Self::Witness>
        + CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Proof: CanonicalSerialize + CanonicalDeserialize;
    type Error;

    fn generate_proof(
        &self,
        witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error>;

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error>;
}

pub trait RecoverSecret<Rhs = Self> {
    type Error;

    fn recover_secret(&self, other: &Rhs) -> Result<Fr, Self::Error>;
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

#[cfg(not(target_arch = "wasm32"))]
impl RLNZkProof for ArkGroth16Backend {
    type Witness = RLNWitnessInputV3;
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNError;

    fn generate_proof(
        &self,
        _witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error> {
        todo!()
    }

    fn verify(&self, _proof: &Self::Proof, _values: &Self::Values) -> Result<bool, Self::Error> {
        todo!()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl RLNPartialZkProof for ArkGroth16Backend {
    type PartialWitness = RLNPartialWitnessInputV3;
    type PartialProof = PartialProof;

    fn generate_partial_proof(
        &self,
        _witness: Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error> {
        todo!()
    }

    fn finish_proof(
        &self,
        _partial: Self::PartialProof,
        _witness: Self::Witness,
    ) -> Result<Self::Proof, Self::Error> {
        todo!()
    }
}
