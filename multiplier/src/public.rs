use ark_circom::{CircomBuilder, CircomConfig, CircomCircuit};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::{
    ProvingKey,
    generate_random_parameters,
    create_random_proof as prove,
    prepare_verifying_key,
    verify_proof
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};

use std::io::{self, Read, Write};


pub struct Multiplier {
    circom: CircomCircuit<Bn254>,
    params: ProvingKey<Bn254>
}

impl Multiplier {
    // TODO Break this apart here
    pub fn new() -> Multiplier {
        let cfg = CircomConfig::<Bn254>::new(
            "./resources/circom2_multiplier2.wasm",
            "./resources/circom2_multiplier2.r1cs",
        ).unwrap();

        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 3);
        builder.push_input("b", 11);

        // create an empty instance for setting it up
        let circom = builder.setup();

        let mut rng = thread_rng();

        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)
            .unwrap();

        let circom = builder.build().unwrap();

        let inputs = circom.get_public_inputs().unwrap();

        Multiplier { circom, params }
    }

    // TODO Input Read
    pub fn prove<W: Write>(&self, mut result_data: W) -> io::Result<()> {
        let mut rng = thread_rng();

        // XXX: There's probably a better way to do this
        let circom = self.circom.clone();
        let params = self.params.clone();

        let proof = prove(circom, &params, &mut rng).unwrap();

        // XXX: Unclear if this is different from other serialization(s)
        let _ = proof.serialize(result_data).unwrap();

        Ok(())
    }

    // TODO Return proof
    pub fn verify() -> bool {
        false
    }
}

#[test]
fn multiplier_proof() {
    let mul = Multiplier::new();
    let inputs = mul.circom.get_public_inputs().unwrap();

    let mut rng = thread_rng();

    let proof = prove(mul.circom, &mul.params, &mut rng).unwrap();

    let pvk = prepare_verifying_key(&mul.params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs).unwrap();

    assert!(verified);
}
