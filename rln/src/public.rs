use crate::poseidon_tree::PoseidonTree;
/// This is the main public API for RLN. It is used by the FFI, and should be
/// used by tests etc as well
///
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig, WitnessCalculator};
use ark_groth16::Proof as ArkProof;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, str::FromStr, UniformRand};
use num_bigint::BigInt;
use semaphore::{identity::Identity, Field};
use serde::{Deserialize, Serialize};
use serde_json;
use std::default::Default;
use std::io::Cursor;
use std::io::{self, Error, ErrorKind, Result}; //default read/write
use std::option::Option;
use std::{sync::Mutex};
use ark_relations::r1cs::ConstraintMatrices;

// For the ToBytes implementation of groth16::Proof
use ark_ec::bn::Bn;
use ark_ff::bytes::ToBytes;
use ark_serialize::{Read, Write};

use crate::circuit::{CIRCOM, TEST_RESOURCES_FOLDER, TEST_TREE_HEIGHT, VK, ZKEY};
use crate::protocol::{self, *};
use crate::utils::*;

// Application specific RLN identifier
pub const RLN_IDENTIFIER: &[u8] = b"zerokit/rln/010203040506070809";

// TODO Add Engine here? i.e. <E: Engine> not <Bn254>
// TODO Assuming we want to use IncrementalMerkleTree, figure out type/trait conversions
pub struct RLN<'a> {
    witness_calculator: &'a Mutex<WitnessCalculator>,
    proving_key: Result<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)>,
    verification_key: Result<VerifyingKey<Bn254>>,
    tree: PoseidonTree,
    resources_folder: String,
}

impl RLN<'_> {
    pub fn new<R: Read>(tree_height: usize, mut input_data: R) -> RLN<'static> {
        // We read input
        let mut input: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input).unwrap();

        let resources_folder = String::from_utf8(input).expect("Found invalid UTF-8");

        let witness_calculator = CIRCOM(&resources_folder);

        let proving_key = ZKEY(&resources_folder);
        let verification_key = VK(&resources_folder);

        // We compute a default empty tree
        let leaf = Field::from(0);
        let tree = PoseidonTree::new(tree_height, leaf);

        RLN {
            witness_calculator,
            proving_key,
            verification_key,
            tree,
            resources_folder,
        }
    }

    ////////////////////////////////////////////////////////
    // Merkle-tree APIs
    ////////////////////////////////////////////////////////
    pub fn set_tree(&mut self, tree_height: usize) -> io::Result<()> {
        // We compute a default empty tree of desired height
        let leaf = Field::from(0);
        self.tree = PoseidonTree::new(tree_height, leaf);

        Ok(())
    }

    pub fn set_leaf<R: Read>(&mut self, index: usize, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte)?;

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_field(&leaf_byte);
        self.tree.set(index, leaf);

        Ok(())
    }

    //TODO: change to set_leaves_from(index, input_data)
    pub fn set_leaves<R: Read>(&mut self, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaves_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaves_byte)?;

        let (leaves, _) = bytes_le_to_vec_field(&leaves_byte);

        // We set the leaves
        for (i, leaf) in leaves.iter().enumerate() {
            self.tree.set(i, *leaf);
        }

        Ok(())
    }

    // Set input leaf to the next available index
    pub fn set_next_leaf<R: Read>(&mut self, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte)?;

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_field(&leaf_byte);
        self.tree.set(self.tree.next_index, leaf);

        Ok(())
    }

    // Deleting a leaf corresponds to set its value to the default 0 leaf
    pub fn delete_leaf(&mut self, index: usize) -> io::Result<()> {
        // We reset the leaf only if we previously set a leaf at that index
        if index < self.tree.next_index {
            let leaf = Field::from(0);
            self.tree.set(index, leaf);
        }

        Ok(())
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_root<W: Write>(&self, mut output_data: W) -> io::Result<()> {
        let root = self.tree.root();
        output_data.write_all(&field_to_bytes_le(&root))?;

        Ok(())
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_proof<W: Write>(&self, index: usize, mut output_data: W) -> io::Result<()> {
        let merkle_proof = self.tree.proof(index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        output_data.write_all(&vec_field_to_bytes_le(&path_elements))?;
        output_data.write_all(&vec_u8_to_bytes_le(&identity_path_index))?;

        Ok(())
    }

    ////////////////////////////////////////////////////////
    // zkSNARK APIs
    ////////////////////////////////////////////////////////
    pub fn prove<R: Read, W: Write>(
        &mut self,
        mut input_data: R,
        mut output_data: W,
    ) -> io::Result<()> {
        // We read input RLN witness and we deserialize it
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let (rln_witness, _) = deserialize_witness(&serialized);

        /*
        if self.witness_calculator.is_none() {
            self.witness_calculator = CIRCOM(&self.resources_folder);
        }
        */

        let proof = generate_proof(
            self.witness_calculator,
            self.proving_key.as_ref().unwrap(),
            &rln_witness,
        )
        .unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        ArkProof::from(proof).serialize(&mut output_data).unwrap();

        Ok(())
    }

    pub fn verify<R: Read>(&self, mut input_data: R) -> io::Result<bool> {
        // Input data is serialized for Bn254 as:
        // serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes)
        let mut input_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input_byte)?;
        let proof: protocol::Proof =
            ArkProof::deserialize(&mut Cursor::new(&input_byte[..128].to_vec()))
                .unwrap()
                .into();
        let (proof_values, _) = deserialize_proof_values(&input_byte[128..].to_vec());

        let verified = verify_proof(
            self.verification_key.as_ref().unwrap(),
            &proof,
            &proof_values,
        )
        .unwrap();

        Ok(verified)
    }

    // This API keeps partial compatibility with kilic's rln public API https://github.com/kilic/rln/blob/7ac74183f8b69b399e3bc96c1ae8ab61c026dc43/src/public.rs#L148
    // input_data is [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
    // output_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
    pub fn generate_rln_proof<R: Read, W: Write>(
        &mut self,
        mut input_data: R,
        mut output_data: W,
    ) -> io::Result<()> {
        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut witness_byte)?;
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut self.tree, &witness_byte);
        let proof_values = proof_values_from_witness(&rln_witness);

        /*
        if self.witness_calculator.is_none() {
            self.witness_calculator = CIRCOM(&self.resources_folder);
        }
        */

        let proof = generate_proof(
            self.witness_calculator,
            self.proving_key.as_ref().unwrap(),
            &rln_witness,
        )
        .unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        ArkProof::from(proof).serialize(&mut output_data).unwrap();
        output_data.write_all(&serialize_proof_values(&proof_values))?;

        Ok(())
    }

    // Input data is serialized for Bn254 as:
    // [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
    pub fn verify_rln_proof<R: Read>(&self, mut input_data: R) -> io::Result<bool> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof: protocol::Proof =
            ArkProof::deserialize(&mut Cursor::new(&serialized[..128].to_vec()))
                .unwrap()
                .into();
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..].to_vec());
        all_read += read;

        let signal_len = usize::try_from(u64::from_le_bytes(
            serialized[all_read..all_read + 8].try_into().unwrap(),
        ))
        .unwrap();
        all_read += 8;

        let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

        let verified = verify_proof(
            self.verification_key.as_ref().unwrap(),
            &proof,
            &proof_values,
        )
        .unwrap();

        // Consistency checks to counter proof tampering
        let x = hash_to_field(&signal);
        Ok(verified
            && (self.tree.root() == proof_values.root)
            && (x == proof_values.x)
            && (proof_values.rln_identifier == hash_to_field(RLN_IDENTIFIER)))
    }

    ////////////////////////////////////////////////////////
    // Utils
    ////////////////////////////////////////////////////////

    pub fn key_gen<W: Write>(&self, mut output_data: W) -> io::Result<()> {
        let (id_key, id_commitment_key) = keygen();
        output_data.write_all(&field_to_bytes_le(&id_key))?;
        output_data.write_all(&field_to_bytes_le(&id_commitment_key))?;

        Ok(())
    }

    pub fn hash<R: Read, W: Write>(&self, mut input_data: R, mut output_data: W) -> io::Result<()> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;

        let hash = hash_to_field(&serialized);
        output_data.write_all(&field_to_bytes_le(&hash))?;

        Ok(())
    }
}

impl Default for RLN<'_> {
    fn default() -> Self {
        let tree_height = TEST_TREE_HEIGHT;
        let buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        Self::new(tree_height, buffer)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::str::FromStr;
    use rand::Rng;
    use semaphore::poseidon_hash;

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Field> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(to_field(&Fr::rand(&mut rng)));
        }

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We check if internal index is properly set
            assert_eq!(rln.tree.next_index, i);

            let mut buffer = Cursor::new(field_to_bytes_le(&leaf));
            rln.set_leaf(i, &mut buffer).unwrap();
        }

        // We get the root of the tree obtained adding one leaf per time
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_single, _) = bytes_le_to_field(&buffer.into_inner());

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let mut buffer = Cursor::new(field_to_bytes_le(&leaf));
            rln.set_next_leaf(&mut buffer).unwrap();
        }

        // We check if internal index is properly set
        assert_eq!(rln.tree.next_index, no_of_leaves);

        // We get the root of the tree obtained adding leaves using the internal index
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_next, _) = bytes_le_to_field(&buffer.into_inner());

        assert_eq!(root_single, root_next);

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_field_to_bytes_le(&leaves));
        rln.set_leaves(&mut buffer).unwrap();

        // We check if internal index is properly set
        assert_eq!(rln.tree.next_index, no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch, _) = bytes_le_to_field(&buffer.into_inner());

        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..2 * no_of_leaves {
            rln.delete_leaf(i).unwrap();
        }

        // We check if internal index is properly set
        assert_eq!(rln.tree.next_index, no_of_leaves);

        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_delete, _) = bytes_le_to_field(&buffer.into_inner());

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_empty, _) = bytes_le_to_field(&buffer.into_inner());

        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public API
    // This test contains hardcoded values!
    // TODO: expand this test to work with tree_height = 20
    fn test_merkle_proof() {
        let tree_height = TEST_TREE_HEIGHT;
        let leaf_index = 3;

        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // generate identity
        // We follow zk-kit approach for identity generation
        let id = Identity::from_seed(b"test-merkle-proof");
        let identity_secret = poseidon_hash(&vec![id.trapdoor, id.nullifier]);
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        // We pass id_commitment as Read buffer to RLN's set_leaf
        let mut buffer = Cursor::new(field_to_bytes_le(&id_commitment));
        rln.set_leaf(leaf_index, &mut buffer).unwrap();

        // We check correct computation of the root
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_field(&buffer.into_inner());

        assert_eq!(
            root,
            Field::from_str("0x27401a4559ce263630907ce3b77c570649e28ede22d2a7f5296839627a16e870")
                .unwrap()
        );

        // We check correct computation of merkle proof
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_proof(leaf_index, &mut buffer).unwrap();

        let buffer_inner = buffer.into_inner();
        let (path_elements, read) = bytes_le_to_vec_field(&buffer_inner);
        let (identity_path_index, _) = bytes_le_to_vec_u8(&buffer_inner[read..].to_vec());

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
            compute_tree_root(&id_commitment, &path_elements, &identity_path_index, false);

        assert_eq!(root, root_from_proof);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public API
    fn test_groth16_proof() {
        let tree_height = TEST_TREE_HEIGHT;

        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // Note: we only test Groth16 proof generation, so we ignore setting the tree in the RLN object
        let rln_witness = random_rln_witness(tree_height);
        let proof_values = proof_values_from_witness(&rln_witness);

        // We compute a Groth16 proof
        let mut input_buffer = Cursor::new(serialize_witness(&rln_witness));
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.prove(&mut input_buffer, &mut output_buffer).unwrap();
        let serialized_proof = output_buffer.into_inner();

        // Before checking public verify API, we check that the (deserialized) proof generated by prove is actually valid
        let proof: protocol::Proof = ArkProof::deserialize(&mut Cursor::new(&serialized_proof))
            .unwrap()
            .into();
        let verified = verify_proof(
            &rln.verification_key.as_ref().unwrap(),
            &proof,
            &proof_values,
        );
        assert!(verified.unwrap());

        // We prepare the input to prove API, consisting of serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes)
        let serialized_proof_values = serialize_proof_values(&proof_values);
        let mut verify_data = Vec::<u8>::new();
        verify_data.extend(&serialized_proof);
        verify_data.extend(&serialized_proof_values);
        let mut input_buffer = Cursor::new(verify_data);

        // We verify the Groth16 proof against the provided proof values
        let verified = rln.verify(&mut input_buffer).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_rln_proof() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Field> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(to_field(&Fr::rand(&mut rng)));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_field_to_bytes_le(&leaves));
        rln.set_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.next_index).unwrap();
        let mut buffer = Cursor::new(field_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        let signal_len = u64::try_from(signal.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut field_to_bytes_le(&identity_secret));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut field_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(serialized);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();

        // output_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = output_buffer.into_inner();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data || signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(proof_data);
        let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_hash_to_field() {
        let rln = RLN::default();

        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        let mut input_buffer = Cursor::new(&signal);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        rln.hash(&mut input_buffer, &mut output_buffer).unwrap();
        let serialized_hash = output_buffer.into_inner();
        let (hash1, _) = bytes_le_to_field(&serialized_hash);

        let hash2 = hash_to_field(&signal);

        assert_eq!(hash1, hash2);
    }
}
