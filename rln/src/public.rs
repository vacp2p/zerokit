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
use crate::protocol::*;
use crate::utils::*;

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

    pub fn set_leaf<R: Read>(&mut self, index: usize, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte);

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_field(leaf_byte);
        self.tree.set(index, leaf);

        Ok(())
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_root<W: Write>(&self, mut output_data: W) -> io::Result<()> {
        let root = self.tree.root();
        output_data.write_all(&field_to_bytes_le(root))?;

        Ok(())
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_proof<W: Write>(&self, index: usize, mut output_data: W) -> io::Result<()> {
        let merkle_proof = self.tree.proof(index).expect("proof should exist");
        let path_elements = get_path_elements(&merkle_proof);
        let identity_path_index = get_identity_path_index(&merkle_proof);

        output_data.write_all(&vec_field_to_bytes_le(path_elements))?;
        output_data.write_all(&vec_u8_to_bytes_le(identity_path_index))?;

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

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::str::FromStr;
    use semaphore::poseidon_hash;
    use std::io::Cursor;

    #[test]
    // This test is similar to the one in lib, but uses only public API
    fn public_test_merkle_proof() {
        let tree_height = 16;
        let leaf_index = 3;

        let mut rln = RLN::new(tree_height);

        // generate identity
        // We follow zk-kit approach for identity generation
        let id = Identity::from_seed(b"test-merkle-proof");
        let identity_secret = poseidon_hash(&vec![id.trapdoor, id.nullifier]);
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        // We pass id_commitment as Read buffer to RLN's set_leaf
        let mut buffer = Cursor::new(field_to_bytes_le(id_commitment));
        rln.set_leaf(leaf_index, &mut buffer).unwrap();

        // We check correct computation of the root
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_field(buffer.into_inner());

        assert_eq!(
            root,
            Field::from_str("0x27401a4559ce263630907ce3b77c570649e28ede22d2a7f5296839627a16e870")
                .unwrap()
        );

        // We check correct computation of proof
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_proof(leaf_index, &mut buffer).unwrap();

        let (path_elements, read) = bytes_le_to_vec_field(buffer.clone().into_inner());
        let (identity_path_index, _) =
            bytes_le_to_vec_u8(buffer.into_inner()[read..].to_vec());

        // We check correct computation of the path and indexes
        let expected_path_elements = vec![
            Field::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            Field::from_str("0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864")
                .unwrap(),
            Field::from_str("0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1")
                .unwrap(),
            Field::from_str("0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238")
                .unwrap(),
            Field::from_str("0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a")
                .unwrap(),
            Field::from_str("0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55")
                .unwrap(),
            Field::from_str("0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78")
                .unwrap(),
            Field::from_str("0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d")
                .unwrap(),
            Field::from_str("0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61")
                .unwrap(),
            Field::from_str("0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747")
                .unwrap(),
            Field::from_str("0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2")
                .unwrap(),
            Field::from_str("0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636")
                .unwrap(),
            Field::from_str("0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a")
                .unwrap(),
            Field::from_str("0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0")
                .unwrap(),
            Field::from_str("0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c")
                .unwrap(),
        ];

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We double check that the proof computed from public API is correct
        let root_from_proof =
            get_tree_root(id_commitment, &path_elements, &identity_path_index, false);

        assert_eq!(root, root_from_proof);
    }
}
