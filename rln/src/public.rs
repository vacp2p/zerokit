/// This is the main public API for RLN. It is used by the FFI, and should be
/// used by tests etc as well
///
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof, ProvingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use semaphore::{
    hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, protocol::*, Field,
};
use serde::Deserialize;
use serde_json;
use std::io::{self, Read, Write};

use crate::circuit::{CIRCOM, ZKEY};
use crate::protocol;

// TODO Add Engine here? i.e. <E: Engine> not <Bn254>
// TODO Assuming we want to use IncrementalMerkleTree, figure out type/trait conversions
// TODO Adopt to new protocol structure
pub struct RLN {
    //pub circom: CircomBuilder<Bn254>,
    pub params: ProvingKey<Bn254>,
    pub tree: PoseidonTree,
}

use crate::utils::{to_field, to_fr};

// TODO Expand API to have better coverage of things needed

impl RLN {
    // TODO Update this to use new protocol
    pub fn new(tree_height: usize) -> RLN {
        //let circom = CIRCOM();

        let params = ZKEY();

        // We compute a default empty tree
        let leaf = Field::from(0);
        let tree = PoseidonTree::new(tree_height, leaf);

        RLN {
            //circom,
            params,
            tree,
        }
    }

    pub fn set_tree<R: Read>(&self, _input_data: R) -> io::Result<()> {
        //Implement leaf and deserialization
        //let leaf = Leaf::deserialize(input_data).unwrap();

        //returns H::Hash, which is a 256 bit hash value
        //let root = self.tree.root();
        // TODO Return root as LE here
        //root.write_le(&mut result_data)?;
        //println!("NYI: root le write buffer {:#?}", root);
        Ok(())
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_root<W: Write>(&self, result_data: W) -> io::Result<()> {
        //let root = self.tree.get_root();
        // Converts PrimeFieldRepr into LE
        //root.into_repr().write_le(&mut result_data)?;

        //returns H::Hash, which is a 256 bit hash value
        let root = self.tree.root();
        println!("Root Field {:#?}", root);
        // TODO Return root as LE here
        //to_fr(root).write_le(&mut result_data)?;
        Ok(())
    }

    // TODO Input Read -> can go in RLN
    //    pub fn prove<W: Write>(&self, result_data: W) -> io::Result<()> {
    //        let mut rng = thread_rng();
    //
    //        // XXX: There's probably a better way to do this
    //        let circom = self.circom.clone();
    //        let params = self.params.clone();
    //
    //        //let proof = create_random_proof(circom, &params, &mut rng)?;
    //
    //        let proof = prove(circom, &params, &mut rng).unwrap();
    //
    //        println!("Proof: {:?}", proof);
    //
    //        // XXX: Unclear if this is different from other serialization(s)
    //        let _ = proof.serialize(result_data).unwrap();
    //
    //        Ok(())
    //    }
    //
    //    pub fn verify<R: Read>(&self, input_data: R) -> io::Result<bool> {
    //        let proof = Proof::deserialize(input_data).unwrap();
    //
    //        let pvk = prepare_verifying_key(&self.params.vk);
    //
    //        // XXX Part of input data?
    //        let inputs = self.circom.get_public_inputs().unwrap();
    //
    //        let verified = verify_proof(&pvk, &proof, &inputs).unwrap();
    //
    //        Ok(verified)
    //    }
}

impl Default for RLN {
    fn default() -> Self {
        let tree_height = 21;
        Self::new(tree_height)
    }
}
