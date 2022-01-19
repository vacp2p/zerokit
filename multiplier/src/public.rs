use ark_circom::{CircomBuilder, CircomConfig, CircomCircuit};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::generate_random_parameters;
use ark_groth16::ProvingKey;


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

    // TODO Return proof
    pub fn prove() -> bool {
        false
    }

    // TODO Return proof
    pub fn verify() -> bool {
        false
    }
}
