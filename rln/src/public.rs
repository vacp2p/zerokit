use crate::circuit::{vk_from_raw, zkey_from_raw, Curve, Fr};
use crate::poseidon_tree::PoseidonTree;
use crate::protocol::*;
use crate::utils::*;
/// This is the main public API for RLN module. It is used by the FFI, and should be
/// used by tests etc as well
use ark_groth16::Proof as ArkProof;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use cfg_if::cfg_if;
use num_bigint::BigInt;
use std::io::Cursor;
use std::io::{self, Result};

cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        use std::default::Default;
        use std::sync::Mutex;
        use crate::circuit::{circom_from_folder, vk_from_folder, circom_from_raw, zkey_from_folder, TEST_RESOURCES_FOLDER, TEST_TREE_HEIGHT};
        use ark_circom::WitnessCalculator;
    } else {
        use std::marker::*;
    }
}

/// The application-specific RLN identifier.
///
/// Prevents a RLN ZK proof generated for one application to be re-used in another one.
pub const RLN_IDENTIFIER: &[u8] = b"zerokit/rln/010203040506070809";

/// The RLN object.
///
/// It implements the methods required to update the internal Merkle Tree, generate and verify RLN ZK proofs.
///
/// I/O is mostly done using writers and readers implementing `std::io::Write` and `std::io::Read`, respectively.
pub struct RLN<'a> {
    proving_key: Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)>,
    verification_key: Result<VerifyingKey<Curve>>,
    tree: PoseidonTree,

    // The witness calculator can't be loaded in zerokit. Since this struct
    // contains a lifetime, a PhantomData is necessary to avoid a compiler
    // error since the lifetime is not being used
    #[cfg(not(target_arch = "wasm32"))]
    witness_calculator: &'a Mutex<WitnessCalculator>,
    #[cfg(target_arch = "wasm32")]
    _marker: PhantomData<&'a ()>,
}

impl RLN<'_> {
    /// Creates a new RLN object by loading circuit resources from a folder.
    ///
    /// Input parameters are
    /// - `tree_height`: the height of the internal Merkle tree
    /// - `input_data`: a reader for the string path of the resource folder containing the ZK circuit (`rln.wasm`), the proving key (`rln_final.zkey`) and the verification key (`verification_key.json`).
    ///
    /// Example:
    /// ```
    /// use std::io::Cursor;
    ///
    /// let tree_height = 20;
    /// let resources = Cursor::new("./resources/tree_height_20/");
    ///
    /// // We create a new RLN instance
    /// let mut rln = RLN::new(tree_height, resources);
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new<R: Read>(tree_height: usize, mut input_data: R) -> RLN<'static> {
        // We read input
        let mut input: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input).unwrap();

        let resources_folder = String::from_utf8(input).expect("Found invalid UTF-8");

        let witness_calculator = circom_from_folder(&resources_folder);

        let proving_key = zkey_from_folder(&resources_folder);
        let verification_key = vk_from_folder(&resources_folder);

        // We compute a default empty tree
        let tree = PoseidonTree::default(tree_height);

        RLN {
            witness_calculator,
            proving_key,
            verification_key,
            tree,
            #[cfg(target_arch = "wasm32")]
            _marker: PhantomData,
        }
    }

    /// Creates a new RLN object by passing circuit resources as byte vectors.
    ///
    /// Input parameters are
    /// - `tree_height`: the height of the internal Merkle tree
    /// - `circom_vec`: a byte vector containing the ZK circuit (`rln.wasm`) as binary file
    /// - `zkey_vec`: a byte vector containing to the proving key (`rln_final.zkey`) as binary file
    /// - `vk_vec`: a byte vector containing to the verification key (`verification_key.json`) as binary file
    ///
    /// Example:
    /// ```
    /// use std::fs::File;
    /// use std::io::Read;
    ///
    /// let tree_height = 20;
    /// let resources_folder = "./resources/tree_height_20/";
    ///
    /// let mut resources: Vec<Vec<u8>> = Vec::new();
    /// for filename in ["rln.wasm", "rln_final.zkey", "verification_key.json"] {
    ///     let fullpath = format!("{resources_folder}{filename}");
    ///     let mut file = File::open(&fullpath).expect("no file found");
    ///     let metadata = std::fs::metadata(&fullpath).expect("unable to read metadata");
    ///     let mut buffer = vec![0; metadata.len() as usize];
    ///     file.read_exact(&mut buffer).expect("buffer overflow");
    ///     resources.push(buffer);
    /// }
    ///
    /// let mut rln = RLN::new_with_params(
    ///     tree_height,
    ///     resources[0].clone(),
    ///     resources[1].clone(),
    ///     resources[2].clone(),
    /// );
    /// ```
    pub fn new_with_params(
        tree_height: usize,
        #[cfg(not(target_arch = "wasm32"))] circom_vec: Vec<u8>,
        zkey_vec: Vec<u8>,
        vk_vec: Vec<u8>,
    ) -> RLN<'static> {
        #[cfg(not(target_arch = "wasm32"))]
        let witness_calculator = circom_from_raw(circom_vec);

        let proving_key = zkey_from_raw(&zkey_vec);
        let verification_key = vk_from_raw(&vk_vec, &zkey_vec);

        // We compute a default empty tree
        let tree = PoseidonTree::default(tree_height);

        RLN {
            #[cfg(not(target_arch = "wasm32"))]
            witness_calculator,
            proving_key,
            verification_key,
            tree,
            #[cfg(target_arch = "wasm32")]
            _marker: PhantomData,
        }
    }

    ////////////////////////////////////////////////////////
    // Merkle-tree APIs
    ////////////////////////////////////////////////////////
    /// Initializes the internal Merkle tree.
    ///
    /// Leaves are set to the default value implemented in PoseidonTree implementation.
    ///
    /// Input values are:
    /// - `tree_height`: the height of the Merkle tree.
    pub fn set_tree(&mut self, tree_height: usize) -> io::Result<()> {
        // We compute a default empty tree of desired height
        self.tree = PoseidonTree::default(tree_height);

        Ok(())
    }

    /// Sets a leaf value at position index in the internal Merkle tree.
    ///
    /// Input values are:
    /// - `index`: the index of the leaf
    /// - `input_data`: a reader for the serialization of the leaf value (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le))
    ///
    /// Example:
    /// ```
    /// use crate::protocol::*;
    ///
    /// // We generate a random id secret and commitment pair
    /// let (identity_secret, id_commitment) = keygen();
    ///
    /// // We define the tree index where id_commitment will be added
    /// let id_index = 10;
    ///
    /// // We serialize id_commitment and pass it to set_leaf
    /// let mut buffer = Cursor::new(serialize_field_element(id_commitment));
    /// rln.set_leaf(id_index, &mut buffer).unwrap();
    /// ```
    pub fn set_leaf<R: Read>(&mut self, index: usize, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte)?;

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_fr(&leaf_byte);
        self.tree.set(index, leaf)?;

        Ok(())
    }

    /// Sets multiple leaves starting from position index in the internal Merkle tree.
    ///
    /// If n leaves are passed as input, these will be set at positions `index`, `index+1`, ..., `index+n-1` respectively.
    ///
    /// This function updates the internal Merkle tree `next_index value indicating the next available index corresponding to a never-set leaf as `next_index = max(next_index, index + n)`.
    ///
    /// Input values are:
    /// - `index`: the index of the first leaf to be set
    /// - `input_data`: a reader for the serialization of multiple leaf values (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le))
    ///
    /// Example:
    /// ```
    /// use rln::circuit::Fr;
    /// use rln::utils::*;
    ///
    /// let start_index = 10;
    /// let no_of_leaves = 256;
    ///
    /// // We generate a vector of random leaves
    /// let mut leaves: Vec<Fr> = Vec::new();
    /// let mut rng = thread_rng();
    /// for _ in 0..no_of_leaves {
    ///     let (_, id_commitment) = keygen();
    ///     leaves.push(id_commitment);
    /// }
    ///
    /// // We add leaves in a batch into the tree
    /// let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
    /// rln.set_leaves_from(index, &mut buffer).unwrap();
    /// ```
    pub fn set_leaves_from<R: Read>(&mut self, index: usize, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaves_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaves_byte)?;

        let (leaves, _) = bytes_le_to_vec_fr(&leaves_byte);

        // We set the leaves
        return self.tree.set_range(index, leaves);
    }

    /// Resets the tree state to default and sets multiple leaves starting from index 0.
    ///
    /// In contrast to [`set_leaves_from`](crate::public::RLN::set_leaves_from), this function resets to 0 the internal `next_index` value, before setting the input leaves values.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of multiple leaf values (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le))
    pub fn init_tree_with_leaves<R: Read>(&mut self, input_data: R) -> io::Result<()> {
        // reset the tree
        // NOTE: this requires the tree to be initialized with the correct height initially
        // TODO: accept tree_height as a parameter and initialize the tree with that height
        self.set_tree(self.tree.depth())?;
        return self.set_leaves_from(0, input_data);
    }

    /// Sets a leaf value at the next available never-set leaf index.
    ///
    /// This function updates the internal Merkle tree `next_index` value indicating the next available index corresponding to a never-set leaf as `next_index = next_index + 1`.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of multiple leaf values (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le))
    ///
    /// Example:
    /// ```
    /// use rln::circuit::Fr;
    /// use rln::utils::*;
    ///
    /// let tree_height = 20;
    /// let start_index = 10;
    /// let no_of_leaves = 256;
    ///
    /// // We reset the tree
    /// rln.set_tree(tree_height).unwrap();
    ///
    /// // Internal Merkle tree next_index value is now 0
    ///
    /// // We generate a vector of random leaves
    /// let mut leaves: Vec<Fr> = Vec::new();
    /// let mut rng = thread_rng();
    /// for _ in 0..no_of_leaves {
    ///     let (_, id_commitment) = keygen();
    ///     leaves.push(id_commitment);
    /// }
    ///
    /// // We add leaves in a batch into the tree
    /// let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
    /// rln.set_leaves_from(index, &mut buffer).unwrap();
    ///
    /// // We set 256 leaves starting from index 10: next_index value is now max(0, 256+10) = 266
    ///
    /// // We set a leaf on next available index
    /// // id_commitment will be set at index 266
    /// let (_, id_commitment) = keygen();
    /// let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
    /// rln.set_next_leaf(&mut buffer).unwrap();
    /// ```
    pub fn set_next_leaf<R: Read>(&mut self, mut input_data: R) -> io::Result<()> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte)?;

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_fr(&leaf_byte);
        self.tree.update_next(leaf)?;

        Ok(())
    }

    /// Sets the value of the leaf at position index to the harcoded default value.
    ///
    /// This function does not change the internal Merkle tree `next_index` value.
    ///
    /// Input values are:
    /// - `index`: the index of the leaf whose value will be reset
    ///
    /// Example
    /// ```
    ///
    /// let index = 10;
    /// rln.delete_leaf(index).unwrap();
    /// ```
    pub fn delete_leaf(&mut self, index: usize) -> io::Result<()> {
        self.tree.delete(index)?;
        Ok(())
    }

    /// Returns the Merkle tree root
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the root value (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le))
    ///
    /// Example
    /// ```
    /// use rln::utils::*;
    ///
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.get_root(&mut buffer).unwrap();
    /// let (root, _) = bytes_le_to_fr(&buffer.into_inner());
    /// ```
    pub fn get_root<W: Write>(&self, mut output_data: W) -> io::Result<()> {
        let root = self.tree.root();
        output_data.write_all(&fr_to_bytes_le(&root))?;

        Ok(())
    }

    /// Returns the Merkle proof of the leaf at position index
    ///
    /// Input values are:
    /// - `index`: the index of the leaf
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the path elements and path indexes (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le) and [`rln::utils::vec_u8_to_bytes_le`](crate::utils::vec_u8_to_bytes_le), respectively)
    ///
    /// Example
    /// ```
    /// use rln::utils::*;
    ///
    /// let index = 10;
    ///
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.get_proof(index, &mut buffer).unwrap();
    ///
    /// let buffer_inner = buffer.into_inner();
    /// let (path_elements, read) = bytes_le_to_vec_fr(&buffer_inner);
    /// let (identity_path_index, _) = bytes_le_to_vec_u8(&buffer_inner[read..].to_vec());
    /// ```
    pub fn get_proof<W: Write>(&self, index: usize, mut output_data: W) -> io::Result<()> {
        let merkle_proof = self.tree.proof(index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        output_data.write_all(&vec_fr_to_bytes_le(&path_elements))?;
        output_data.write_all(&vec_u8_to_bytes_le(&identity_path_index))?;

        Ok(())
    }

    ////////////////////////////////////////////////////////
    // zkSNARK APIs
    ////////////////////////////////////////////////////////
    /// Computes a zkSNARK RLN proof using a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput).
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object, containing the public and private inputs to the ZK circuits (serialization done using [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness))
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the zkSNARK proof
    ///
    /// Example:
    /// ```
    /// use rln::protocol::*;
    ///
    /// let rln_witness = random_rln_witness(tree_height);
    /// let proof_values = proof_values_from_witness(&rln_witness);
    ///
    /// // We compute a Groth16 proof
    /// let mut input_buffer = Cursor::new(serialize_witness(&rln_witness));
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.prove(&mut input_buffer, &mut output_buffer).unwrap();
    /// let zk_proof = output_buffer.into_inner();
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
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
            &mut self.witness_calculator,
            self.proving_key.as_ref().unwrap(),
            &rln_witness,
        )
        .unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        proof.serialize(&mut output_data).unwrap();

        Ok(())
    }

    /// Verifies a zkSNARK RLN proof.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of the RLN zkSNARK proof concatenated with a serialization of the circuit output values, i.e. `[ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]`, where <_> indicates the byte length.
    ///
    /// The function returns true if the zkSNARK proof is valid with respect to the provided circuit output values, false otherwise.
    ///
    /// Example:
    /// ```
    /// use rln::protocol::*;
    ///
    /// let rln_witness = random_rln_witness(tree_height);
    ///
    /// // We compute a Groth16 proof
    /// let mut input_buffer = Cursor::new(serialize_witness(&rln_witness));
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.prove(&mut input_buffer, &mut output_buffer).unwrap();
    /// let zk_proof = output_buffer.into_inner();
    ///
    /// // We prepare the input to prove API, consisting of zk_proof (compressed, 4*32 bytes) || proof_values (6*32 bytes)
    /// // In this example, we compute proof values directly from witness using the utility proof_values_from_witness
    /// let proof_values = proof_values_from_witness(&rln_witness);
    /// let serialized_proof_values = serialize_proof_values(&proof_values);
    ///
    /// // We build the input to the verify method
    /// let mut verify_data = Vec::<u8>::new();
    /// verify_data.extend(&zk_proof);
    /// verify_data.extend(&proof_values);
    /// let mut input_buffer = Cursor::new(verify_data);
    ///
    /// // We verify the Groth16 proof against the provided zk-proof and proof values
    /// let verified = rln.verify(&mut input_buffer).unwrap();
    ///
    /// assert!(verified);
    /// ```
    pub fn verify<R: Read>(&self, mut input_data: R) -> io::Result<bool> {
        // Input data is serialized for Curve as:
        // serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes), i.e.
        // [ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]
        let mut input_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input_byte)?;
        let proof = ArkProof::deserialize(&mut Cursor::new(&input_byte[..128].to_vec())).unwrap();

        let (proof_values, _) = deserialize_proof_values(&input_byte[128..].to_vec());

        let verified = verify_proof(
            self.verification_key.as_ref().unwrap(),
            &proof,
            &proof_values,
        )
        .unwrap();

        Ok(verified)
    }

    /// Computes a zkSNARK RLN proof from the identity secret, the Merkle tree index, the epoch and signal.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of `[ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]`
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the zkSNARK proof and the circuit evaluations outputs, i.e. `[ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]`
    ///
    /// Example    
    /// ```
    /// use rln::protocol::*:
    /// use rln::utils::*;
    ///
    /// // Generate identity pair
    /// let (identity_secret, id_commitment) = keygen();
    ///
    /// // We set as leaf id_commitment after storing its index
    /// let identity_index = 10;
    /// let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
    /// rln.set_leaf(identity_index, &mut buffer).unwrap();
    ///
    /// // We generate a random signal
    /// let mut rng = rand::thread_rng();
    /// let signal: [u8; 32] = rng.gen();
    /// let signal_len = u64::try_from(signal.len()).unwrap();
    ///
    /// // We generate a random epoch
    /// let epoch = hash_to_field(b"test-epoch");
    ///
    /// // We prepare input for generate_rln_proof API
    /// // input_data is [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
    /// let mut serialized: Vec<u8> = Vec::new();
    /// serialized.append(&mut fr_to_bytes_le(&identity_secret));
    /// serialized.append(&mut identity_index.to_le_bytes().to_vec());
    /// serialized.append(&mut fr_to_bytes_le(&epoch));
    /// serialized.append(&mut signal_len.to_le_bytes().to_vec());
    /// serialized.append(&mut signal.to_vec());
    ///
    /// let mut input_buffer = Cursor::new(serialized);
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
    ///     .unwrap();
    ///
    /// // proof_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
    /// let mut proof_data = output_buffer.into_inner();
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
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

        let proof = generate_proof(
            self.witness_calculator,
            self.proving_key.as_ref().unwrap(),
            &rln_witness,
        )
        .unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize(&mut output_data).unwrap();
        output_data.write_all(&serialize_proof_values(&proof_values))?;

        Ok(())
    }

    // TODO: this function seems to use redundant witness (as bigint and serialized) and should be refactored
    // Generate RLN Proof using a witness calculated from outside zerokit
    //
    // output_data is  [ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]
    // we skip it from documentation for now
    #[doc(hidden)]
    pub fn generate_rln_proof_with_witness<W: Write>(
        &mut self,
        calculated_witness: Vec<BigInt>,
        rln_witness_vec: Vec<u8>,
        mut output_data: W,
    ) -> io::Result<()> {
        let (rln_witness, _) = deserialize_witness(&rln_witness_vec[..]);
        let proof_values = proof_values_from_witness(&rln_witness);

        let proof =
            generate_proof_with_witness(calculated_witness, self.proving_key.as_ref().unwrap())
                .unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize(&mut output_data).unwrap();
        output_data.write_all(&serialize_proof_values(&proof_values))?;
        Ok(())
    }

    /// Verifies a zkSNARK RLN proof against the provided proof values and the state of the internal Merkle tree.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of the RLN zkSNARK proof concatenated with a serialization of the circuit output values and the signal information, i.e. `[ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> | signal_len<8> | signal<var> ]`
    ///
    /// The function returns true if the zkSNARK proof is valid with respect to the provided circuit output values and signal. Returns false otherwise.
    ///
    /// Note that contrary to [`verify`](crate::public::RLN::verify), this function takes additionaly as input the signal and further verifies if
    /// - the Merkle tree root corresponds to the root provided as input;
    /// - the input signal corresponds to the Shamir's x coordinate provided as input
    /// - the hardcoded application [RLN identifier](crate::public::RLN_IDENTIFIER) corresponds to the RLN identifier provided as input
    ///
    /// Example
    /// ```
    /// // proof_data is computed as in the example code snippet provided for rln::public::RLN::generate_rln_proof
    ///
    /// // We prepare input for verify_rln_proof API
    /// // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
    /// // that is [ proof_data || signal_len<8> | signal<var> ]
    /// proof_data.append(&mut signal_len.to_le_bytes().to_vec());
    /// proof_data.append(&mut signal.to_vec());
    ///
    /// let mut input_buffer = Cursor::new(proof_data);
    /// let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();
    ///
    /// assert!(verified);
    /// ```
    pub fn verify_rln_proof<R: Read>(&self, mut input_data: R) -> io::Result<bool> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized[..128].to_vec())).unwrap();
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..].to_vec());
        all_read += read;

        let signal_len =
            u64::from_le_bytes(serialized[all_read..all_read + 8].try_into().unwrap()) as usize;
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

    /// Verifies a zkSNARK RLN proof against the provided proof values and a set of allowed Merkle tree roots.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of the RLN zkSNARK proof concatenated with a serialization of the circuit output values and the signal information, i.e. `[ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> | signal_len<8> | signal<var> ]`
    /// - `roots_data`: a reader for the serialization of a vector of roots, i.e. `[ number_of_roots<8> | root_1<32> | ... | root_n<32> ]` (number_of_roots is a uint64 in little-endian, roots are serialized using `rln::utils::fr_to_bytes_le`))
    ///
    /// The function returns true if the zkSNARK proof is valid with respect to the provided circuit output values, signal and roots. Returns false otherwise.
    ///
    /// Note that contrary to [`verify_rln_proof`](crate::public::RLN::verify_rln_proof), this function does not check if the internal Merkle tree root corresponds to the root provided as input, but rather checks if the root provided as input in `input_data` corresponds to one of the roots serialized in `roots_data`.
    ///
    /// If `roots_data` contains no root (is empty), root validation is skipped and the proof will be correctly verified only if the other proof values results valid (i.e., zk-proof, signal, x-coordinate, RLN identifier)
    ///   
    /// Example
    /// ```
    /// // proof_data is computed as in the example code snippet provided for rln::public::RLN::generate_rln_proof
    ///
    /// // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
    /// let mut input_buffer = Cursor::new(proof_data);
    /// let mut roots_serialized: Vec<u8> = Vec::new();
    /// let mut roots_buffer = Cursor::new(roots_serialized.clone());
    /// let verified = rln
    ///     .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
    ///     .unwrap();
    ///
    /// assert!(verified);
    ///
    /// // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
    /// for _ in 0..5 {
    ///     roots_serialized.append(&mut fr_to_bytes_le(&Fr::rand(&mut rng)));
    /// }
    /// roots_buffer = Cursor::new(roots_serialized.clone());
    /// let verified = rln
    ///     .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
    ///     .unwrap();
    ///
    /// assert!(verified == false);
    ///
    /// // We get the root of the tree obtained adding one leaf per time
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.get_root(&mut buffer).unwrap();
    /// let (root, _) = bytes_le_to_fr(&buffer.into_inner());
    ///
    /// // We add the real root and we check if now the proof is verified
    /// roots_serialized.append(&mut fr_to_bytes_le(&root));
    /// roots_buffer = Cursor::new(roots_serialized.clone());
    /// let verified = rln
    ///     .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
    ///     .unwrap();
    ///
    /// assert!(verified);
    /// ```
    pub fn verify_with_roots<R: Read>(
        &self,
        mut input_data: R,
        mut roots_data: R,
    ) -> io::Result<bool> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized[..128].to_vec())).unwrap();
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..].to_vec());
        all_read += read;

        let signal_len =
            u64::from_le_bytes(serialized[all_read..all_read + 8].try_into().unwrap()) as usize;
        all_read += 8;

        let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

        let verified = verify_proof(
            self.verification_key.as_ref().unwrap(),
            &proof,
            &proof_values,
        )
        .unwrap();

        // First consistency checks to counter proof tampering
        let x = hash_to_field(&signal);
        let partial_result = verified
            && (x == proof_values.x)
            && (proof_values.rln_identifier == hash_to_field(RLN_IDENTIFIER));

        // We skip root validation if proof is already invalid
        if partial_result == false {
            return Ok(partial_result);
        }

        // We read passed roots
        let mut roots_serialized: Vec<u8> = Vec::new();
        roots_data.read_to_end(&mut roots_serialized)?;

        // The vector where we'll store read roots
        let mut roots: Vec<Fr> = Vec::new();

        // We expect each root to be fr_byte_size() bytes long.
        let fr_size = fr_byte_size();

        // We read the buffer and convert to Fr as much as we can
        all_read = 0;
        while all_read + fr_size <= roots_serialized.len() {
            let (root, read) = bytes_le_to_fr(&roots_serialized[all_read..]);
            all_read += read;
            roots.push(root);
        }

        // We validate the root
        let roots_verified: bool;
        if roots.is_empty() {
            // If no root is passed in roots_buffer, we skip proof's root check
            roots_verified = true;
        } else {
            // Otherwise we check if proof's root is contained in the passed buffer
            roots_verified = roots.contains(&proof_values.root);
        }

        // We combine all checks
        Ok(partial_result && roots_verified)
    }

    ////////////////////////////////////////////////////////
    // Utils
    ////////////////////////////////////////////////////////

    /// Returns an identity secret and identity commitment pair.
    ///
    /// The identity commitment is the Poseidon hash of the identity secret.
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the identity secret and identity commitment (serialization done with `rln::utils::fr_to_bytes_le`)
    ///
    /// Example
    /// ```
    /// use rln::protocol::*;
    ///
    /// // We generate an identity pair
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.key_gen(&mut buffer).unwrap();
    ///
    /// // We deserialize the keygen output
    /// let (identity_secret, id_commitment) = deserialize_identity_pair(buffer.into_inner());
    /// ```
    pub fn key_gen<W: Write>(&self, mut output_data: W) -> io::Result<()> {
        let (id_key, id_commitment_key) = keygen();
        output_data.write_all(&fr_to_bytes_le(&id_key))?;
        output_data.write_all(&fr_to_bytes_le(&id_commitment_key))?;

        Ok(())
    }

    /// Returns an identity secret and identity commitment pair generated using a seed.
    ///
    /// The identity commitment is the Poseidon hash of the identity secret.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the byte vector containing the seed
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the identity secret and identity commitment (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le))
    ///
    /// Example
    /// ```
    /// use rln::protocol::*;
    ///
    /// let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    ///
    /// let mut input_buffer = Cursor::new(&seed_bytes);
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.seeded_key_gen(&mut input_buffer, &mut output_buffer)
    ///     .unwrap();
    ///
    /// // We deserialize the keygen output
    /// let (identity_secret, id_commitment) = deserialize_identity_pair(output_buffer.into_inner());
    /// ```
    pub fn seeded_key_gen<R: Read, W: Write>(
        &self,
        mut input_data: R,
        mut output_data: W,
    ) -> io::Result<()> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;

        let (id_key, id_commitment_key) = seeded_keygen(&serialized);
        output_data.write_all(&fr_to_bytes_le(&id_key))?;
        output_data.write_all(&fr_to_bytes_le(&id_commitment_key))?;

        Ok(())
    }

    /// Hashes an input signal to an element in the working prime field.
    ///
    /// The result is computed as the Keccak256 of the input signal modulo the prime field characteristic.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the byte vector containing the input signal.
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the resulting field element (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le))
    ///
    /// Example
    /// ```
    /// let signal: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    ///
    /// let mut input_buffer = Cursor::new(&signal);
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.hash(&mut input_buffer, &mut output_buffer)
    ///     .unwrap();
    ///
    /// // We deserialize the keygen output
    /// let field_element = deserialize_field_element(output_buffer.into_inner());
    /// ```
    pub fn hash<R: Read, W: Write>(&self, mut input_data: R, mut output_data: W) -> io::Result<()> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;

        let hash = hash_to_field(&serialized);
        output_data.write_all(&fr_to_bytes_le(&hash))?;

        Ok(())
    }

    /// Returns the serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) populated from the identity secret, the Merkle tree index, the epoch and signal.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of `[ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]`
    ///
    /// The function returns the corresponding [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object serialized using [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness)).
    pub fn get_serialized_rln_witness<R: Read>(&mut self, mut input_data: R) -> Vec<u8> {
        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut witness_byte).unwrap();
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut self.tree, &witness_byte);

        serialize_witness(&rln_witness)
    }

    /// Converts a byte serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object to the corresponding JSON serialization.
    ///
    /// Input values are:
    /// - `serialized_witness`: the byte serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object (serialization done with  [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness)).
    ///
    /// The function returns the corresponding JSON encoding of the input [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object.
    pub fn get_rln_witness_json(
        &mut self,
        serialized_witness: &[u8],
    ) -> io::Result<serde_json::Value> {
        let (rln_witness, _) = deserialize_witness(serialized_witness);
        Ok(get_json_inputs(&rln_witness))
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
    use crate::poseidon_hash::poseidon_hash;
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We check if the number of leaves set is consistent
            assert_eq!(rln.tree.leaves_set(), i);

            let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
            rln.set_leaf(i, &mut buffer).unwrap();
        }

        // We get the root of the tree obtained adding one leaf per time
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_single, _) = bytes_le_to_fr(&buffer.into_inner());

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
            rln.set_next_leaf(&mut buffer).unwrap();
        }

        // We check if numbers of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves using the internal index
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_next, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_single, root_next);

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..2 * no_of_leaves {
            rln.delete_leaf(i).unwrap();
        }

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_delete, _) = bytes_le_to_fr(&buffer.into_inner());

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // We test leaf setting with a custom index, to enable batch updates to the root
    // Uses `set_leaves_from` to set leaves in a batch, from index `start_index`
    fn test_leaf_setting_with_index() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let set_index = rng.gen_range(0..no_of_leaves) as usize;

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch_with_init, _) = bytes_le_to_fr(&buffer.into_inner());

        // `init_tree_with_leaves` resets the tree to the height it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[0..set_index]));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We add the remaining n leaves in a batch starting from index m
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[set_index..]));
        rln.set_leaves_from(set_index, &mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch_with_custom_index, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_batch_with_init, root_batch_with_custom_index);

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
            rln.set_next_leaf(&mut buffer).unwrap();
        }

        // We check if numbers of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves using the internal index
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_single_additions, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_batch_with_init, root_single_additions);
    }

    #[test]
    // This test checks if `set_leaves_from` throws an error when the index is out of bounds
    fn test_set_leaves_bad_index() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }
        let bad_index = (1 << tree_height) - rng.gen_range(0..no_of_leaves) as usize;

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // Get root of empty tree
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.set_leaves_from(bad_index, &mut buffer)
            .expect_err("Should throw an error");

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), 0);

        // Get the root of the tree
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_after_bad_set, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public API
    fn test_merkle_proof() {
        let tree_height = TEST_TREE_HEIGHT;
        let leaf_index = 3;

        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // generate identity
        let identity_secret = hash_to_field(b"test-merkle-proof");
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        // We pass id_commitment as Read buffer to RLN's set_leaf
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_leaf(leaf_index, &mut buffer).unwrap();

        // We check correct computation of the root
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_fr(&buffer.into_inner());

        if TEST_TREE_HEIGHT == 15 {
            assert_eq!(
                root,
                str_to_fr(
                    "0x1984f2e01184aef5cb974640898a5f5c25556554e2b06d99d4841badb8b198cd",
                    16
                )
            );
        } else if TEST_TREE_HEIGHT == 19 {
            assert_eq!(
                root,
                str_to_fr(
                    "0x219ceb53f2b1b7a6cf74e80d50d44d68ecb4a53c6cc65b25593c8d56343fb1fe",
                    16
                )
            );
        } else if TEST_TREE_HEIGHT == 20 {
            assert_eq!(
                root,
                str_to_fr(
                    "0x21947ffd0bce0c385f876e7c97d6a42eec5b1fe935aab2f01c1f8a8cbcc356d2",
                    16
                )
            );
        }

        // We check correct computation of merkle proof
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_proof(leaf_index, &mut buffer).unwrap();

        let buffer_inner = buffer.into_inner();
        let (path_elements, read) = bytes_le_to_vec_fr(&buffer_inner);
        let (identity_path_index, _) = bytes_le_to_vec_u8(&buffer_inner[read..].to_vec());

        // We check correct computation of the path and indexes
        let mut expected_path_elements = vec![
            str_to_fr(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                16,
            ),
            str_to_fr(
                "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
                16,
            ),
            str_to_fr(
                "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
                16,
            ),
            str_to_fr(
                "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
                16,
            ),
            str_to_fr(
                "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
                16,
            ),
            str_to_fr(
                "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
                16,
            ),
            str_to_fr(
                "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
                16,
            ),
            str_to_fr(
                "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
                16,
            ),
            str_to_fr(
                "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
                16,
            ),
            str_to_fr(
                "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
                16,
            ),
            str_to_fr(
                "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
                16,
            ),
            str_to_fr(
                "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
                16,
            ),
            str_to_fr(
                "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
                16,
            ),
            str_to_fr(
                "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
                16,
            ),
            str_to_fr(
                "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
                16,
            ),
        ];

        let mut expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // We add the remaining elements for the case TEST_TREE_HEIGHT = 20
        if TEST_TREE_HEIGHT == 19 || TEST_TREE_HEIGHT == 20 {
            expected_path_elements.append(&mut vec![
                str_to_fr(
                    "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
                    16,
                ),
                str_to_fr(
                    "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
                    16,
                ),
                str_to_fr(
                    "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
                    16,
                ),
                str_to_fr(
                    "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
                    16,
                ),
            ]);
            expected_identity_path_index.append(&mut vec![0, 0, 0, 0]);
        }

        if TEST_TREE_HEIGHT == 20 {
            expected_path_elements.append(&mut vec![str_to_fr(
                "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
                16,
            )]);
            expected_identity_path_index.append(&mut vec![0]);
        }

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
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized_proof)).unwrap();
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
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
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
        serialized.append(&mut fr_to_bytes_le(&identity_secret));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
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
    fn test_rln_with_witness() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
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
        serialized.append(&mut fr_to_bytes_le(&identity_secret));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(serialized);

        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_buffer.read_to_end(&mut witness_byte).unwrap();
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut rln.tree, &witness_byte);

        let serialized_witness = serialize_witness(&rln_witness);

        // Calculate witness outside zerokit (simulating what JS is doing)
        let inputs = inputs_for_witness_calculation(&rln_witness)
            .into_iter()
            .map(|(name, values)| (name.to_string(), values));
        let calculated_witness = rln
            .witness_calculator
            .lock()
            .expect("witness_calculator mutex should not get poisoned")
            .calculate_witness_element::<Curve, _>(inputs, false)
            .map_err(ProofError::WitnessError)
            .unwrap();

        let calculated_witness_vec: Vec<BigInt> = calculated_witness
            .into_iter()
            .map(|v| to_bigint(&v))
            .collect();

        // Generating the proof
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof_with_witness(
            calculated_witness_vec,
            serialized_witness,
            &mut output_buffer,
        )
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
    fn test_seeded_keygen() {
        let rln = RLN::default();

        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        rln.seeded_key_gen(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_secret, read) = bytes_le_to_fr(&serialized_output);
        let (id_commitment, _) = bytes_le_to_fr(&serialized_output[read..].to_vec());

        // We check against expected values
        let expected_identity_secret_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        );

        assert_eq!(identity_secret, expected_identity_secret_seed_bytes);
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
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
        let (hash1, _) = bytes_le_to_fr(&serialized_hash);

        let hash2 = hash_to_field(&signal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn proof_verification_with_roots() {
        // The first part is similar to test_rln_with_witness
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
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
        serialized.append(&mut fr_to_bytes_le(&identity_secret));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
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
        let input_buffer = Cursor::new(proof_data);

        // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
        let mut roots_serialized: Vec<u8> = Vec::new();
        let mut roots_buffer = Cursor::new(roots_serialized.clone());
        let verified = rln
            .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
            .unwrap();

        assert!(verified);

        // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
        for _ in 0..5 {
            roots_serialized.append(&mut fr_to_bytes_le(&Fr::rand(&mut rng)));
        }
        roots_buffer = Cursor::new(roots_serialized.clone());
        let verified = rln
            .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
            .unwrap();

        assert!(verified == false);

        // We get the root of the tree obtained adding one leaf per time
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_fr(&buffer.into_inner());

        // We add the real root and we check if now the proof is verified
        roots_serialized.append(&mut fr_to_bytes_le(&root));
        roots_buffer = Cursor::new(roots_serialized.clone());
        let verified = rln
            .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
            .unwrap();

        assert!(verified);
    }
}
