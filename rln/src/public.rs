use crate::circuit::{vk_from_raw, zkey_from_raw, Curve, Fr};
use crate::poseidon_hash::poseidon_hash as utils_poseidon_hash;
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
use color_eyre::Result;
use num_bigint::BigInt;
use std::io::Cursor;

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
    proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
    verification_key: VerifyingKey<Curve>,
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
    pub fn new<R: Read>(tree_height: usize, mut input_data: R) -> Result<RLN<'static>> {
        // We read input
        let mut input: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input)?;

        let resources_folder = String::from_utf8(input)?;

        let witness_calculator = circom_from_folder(&resources_folder)?;

        let proving_key = zkey_from_folder(&resources_folder)?;
        let verification_key = vk_from_folder(&resources_folder)?;

        // We compute a default empty tree
        let tree = PoseidonTree::default(tree_height);

        Ok(RLN {
            witness_calculator,
            proving_key,
            verification_key,
            tree,
            #[cfg(target_arch = "wasm32")]
            _marker: PhantomData,
        })
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
    ) -> Result<RLN<'static>> {
        #[cfg(not(target_arch = "wasm32"))]
        let witness_calculator = circom_from_raw(circom_vec)?;

        let proving_key = zkey_from_raw(&zkey_vec)?;
        let verification_key = vk_from_raw(&vk_vec, &zkey_vec)?;

        // We compute a default empty tree
        let tree = PoseidonTree::default(tree_height);

        Ok(RLN {
            #[cfg(not(target_arch = "wasm32"))]
            witness_calculator,
            proving_key,
            verification_key,
            tree,
            #[cfg(target_arch = "wasm32")]
            _marker: PhantomData,
        })
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
    pub fn set_tree(&mut self, tree_height: usize) -> Result<()> {
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
    /// // We generate a random identity secret hash and commitment pair
    /// let (identity_secret_hash, id_commitment) = keygen();
    ///
    /// // We define the tree index where id_commitment will be added
    /// let id_index = 10;
    ///
    /// // We serialize id_commitment and pass it to set_leaf
    /// let mut buffer = Cursor::new(serialize_field_element(id_commitment));
    /// rln.set_leaf(id_index, &mut buffer).unwrap();
    /// ```
    pub fn set_leaf<R: Read>(&mut self, index: usize, mut input_data: R) -> Result<()> {
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
    pub fn set_leaves_from<R: Read>(&mut self, index: usize, mut input_data: R) -> Result<()> {
        // We read input
        let mut leaves_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaves_byte)?;

        let (leaves, _) = bytes_le_to_vec_fr(&leaves_byte)?;

        // We set the leaves
        self.tree.set_range(index, leaves)
    }

    /// Resets the tree state to default and sets multiple leaves starting from index 0.
    ///
    /// In contrast to [`set_leaves_from`](crate::public::RLN::set_leaves_from), this function resets to 0 the internal `next_index` value, before setting the input leaves values.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of multiple leaf values (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le))
    pub fn init_tree_with_leaves<R: Read>(&mut self, input_data: R) -> Result<()> {
        // reset the tree
        // NOTE: this requires the tree to be initialized with the correct height initially
        // TODO: accept tree_height as a parameter and initialize the tree with that height
        self.set_tree(self.tree.depth())?;
        self.set_leaves_from(0, input_data)
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
    pub fn set_next_leaf<R: Read>(&mut self, mut input_data: R) -> Result<()> {
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
    pub fn delete_leaf(&mut self, index: usize) -> Result<()> {
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
    pub fn get_root<W: Write>(&self, mut output_data: W) -> Result<()> {
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
    pub fn get_proof<W: Write>(&self, index: usize, mut output_data: W) -> Result<()> {
        let merkle_proof = self.tree.proof(index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        output_data.write_all(&vec_fr_to_bytes_le(&path_elements)?)?;
        output_data.write_all(&vec_u8_to_bytes_le(&identity_path_index)?)?;

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
    ) -> Result<()> {
        // We read input RLN witness and we deserialize it
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let (rln_witness, _) = deserialize_witness(&serialized)?;

        /*
        if self.witness_calculator.is_none() {
            self.witness_calculator = CIRCOM(&self.resources_folder);
        }
        */

        let proof = generate_proof(self.witness_calculator, &self.proving_key, &rln_witness)?;

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        proof.serialize(&mut output_data)?;

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
    pub fn verify<R: Read>(&self, mut input_data: R) -> Result<bool> {
        // Input data is serialized for Curve as:
        // serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes), i.e.
        // [ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]
        let mut input_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input_byte)?;
        let proof = ArkProof::deserialize(&mut Cursor::new(&input_byte[..128]))?;

        let (proof_values, _) = deserialize_proof_values(&input_byte[128..]);

        let verified = verify_proof(&self.verification_key, &proof, &proof_values)?;

        Ok(verified)
    }

    /// Computes a zkSNARK RLN proof from the identity secret, the Merkle tree index, the epoch and signal.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of `[ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]`
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
    /// let (identity_secret_hash, id_commitment) = keygen();
    ///
    /// // We set as leaf id_commitment after storing its index
    /// let identity_index = 10;
    /// let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
    /// rln.set_leaf(identity_index, &mut buffer).unwrap();
    ///
    /// // We generate a random signal
    /// let mut rng = rand::thread_rng();
    /// let signal: [u8; 32] = rng.gen();
    /// // We generate a random epoch
    /// let epoch = hash_to_field(b"test-epoch");
    ///
    /// // We prepare input for generate_rln_proof API
    /// // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
    /// let mut serialized: Vec<u8> = Vec::new();
    /// serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
    /// serialized.append(&mut normalize_usize(identity_index));
    /// serialized.append(&mut fr_to_bytes_le(&epoch));
    /// serialized.append(&mut normalize_usize(signal_len).resize(8,0));
    /// serialized.append(&mut signal.to_vec());
    ///
    /// let mut input_buffer = Cursor::new(serialized);
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
    ///     .unwrap();
    ///
    /// // proof_data is [ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> |  rln_identifier<32> ]
    /// let mut proof_data = output_buffer.into_inner();
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate_rln_proof<R: Read, W: Write>(
        &mut self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<()> {
        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut witness_byte)?;
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut self.tree, &witness_byte)?;
        let proof_values = proof_values_from_witness(&rln_witness);

        let proof = generate_proof(self.witness_calculator, &self.proving_key, &rln_witness)?;

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize(&mut output_data)?;
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
    ) -> Result<()> {
        let (rln_witness, _) = deserialize_witness(&rln_witness_vec[..])?;
        let proof_values = proof_values_from_witness(&rln_witness);

        let proof = generate_proof_with_witness(calculated_witness, &self.proving_key).unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize(&mut output_data)?;
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
    /// proof_data.append(&mut normalize_usize(signal_len));
    /// proof_data.append(&mut signal.to_vec());
    ///
    /// let mut input_buffer = Cursor::new(proof_data);
    /// let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();
    ///
    /// assert!(verified);
    /// ```
    pub fn verify_rln_proof<R: Read>(&self, mut input_data: R) -> Result<bool> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized[..128].to_vec()))?;
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..]);
        all_read += read;

        let signal_len = usize::from_le_bytes(serialized[all_read..all_read + 8].try_into()?);
        all_read += 8;

        let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

        let verified = verify_proof(&self.verification_key, &proof, &proof_values)?;

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
    pub fn verify_with_roots<R: Read>(&self, mut input_data: R, mut roots_data: R) -> Result<bool> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized[..128].to_vec()))?;
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..]);
        all_read += read;

        let signal_len = usize::from_le_bytes(serialized[all_read..all_read + 8].try_into()?);
        all_read += 8;

        let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

        let verified = verify_proof(&self.verification_key, &proof, &proof_values)?;

        // First consistency checks to counter proof tampering
        let x = hash_to_field(&signal);
        let partial_result = verified
            && (x == proof_values.x)
            && (proof_values.rln_identifier == hash_to_field(RLN_IDENTIFIER));

        // We skip root validation if proof is already invalid
        if !partial_result {
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
        let roots_verified: bool = if roots.is_empty() {
            // If no root is passed in roots_buffer, we skip proof's root check
            true
        } else {
            // Otherwise we check if proof's root is contained in the passed buffer
            roots.contains(&proof_values.root)
        };

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
    /// let (identity_secret_hash, id_commitment) = deserialize_identity_pair(buffer.into_inner());
    /// ```
    pub fn key_gen<W: Write>(&self, mut output_data: W) -> Result<()> {
        let (identity_secret_hash, id_commitment) = keygen();
        output_data.write_all(&fr_to_bytes_le(&identity_secret_hash))?;
        output_data.write_all(&fr_to_bytes_le(&id_commitment))?;

        Ok(())
    }

    /// Returns an identity trapdoor, nullifier, secret and commitment tuple.
    ///
    /// The identity secret is the Poseidon hash of the identity trapdoor and identity nullifier.
    ///
    /// The identity commitment is the Poseidon hash of the identity secret.
    ///
    /// Generated credentials are compatible with [Semaphore](https://semaphore.appliedzkp.org/docs/guides/identities)'s credentials.
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the identity tapdoor, identity nullifier, identity secret and identity commitment (serialization done with `rln::utils::fr_to_bytes_le`)
    ///
    /// Example
    /// ```
    /// use rln::protocol::*;
    ///
    /// // We generate an identity tuple
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.extended_key_gen(&mut buffer).unwrap();
    ///
    /// // We deserialize the keygen output
    /// let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) = deserialize_identity_tuple(buffer.into_inner());
    /// ```
    pub fn extended_key_gen<W: Write>(&self, mut output_data: W) -> Result<()> {
        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            extended_keygen();
        output_data.write_all(&fr_to_bytes_le(&identity_trapdoor))?;
        output_data.write_all(&fr_to_bytes_le(&identity_nullifier))?;
        output_data.write_all(&fr_to_bytes_le(&identity_secret_hash))?;
        output_data.write_all(&fr_to_bytes_le(&id_commitment))?;

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
    /// let (identity_secret_hash, id_commitment) = deserialize_identity_pair(output_buffer.into_inner());
    /// ```
    pub fn seeded_key_gen<R: Read, W: Write>(
        &self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<()> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;

        let (identity_secret_hash, id_commitment) = seeded_keygen(&serialized);
        output_data.write_all(&fr_to_bytes_le(&identity_secret_hash))?;
        output_data.write_all(&fr_to_bytes_le(&id_commitment))?;

        Ok(())
    }

    /// Returns an identity trapdoor, nullifier, secret and commitment tuple generated using a seed.
    ///
    /// The identity secret is the Poseidon hash of the identity trapdoor and identity nullifier.
    ///
    /// The identity commitment is the Poseidon hash of the identity secret.
    ///
    /// Generated credentials are compatible with [Semaphore](https://semaphore.appliedzkp.org/docs/guides/identities)'s credentials.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the byte vector containing the seed
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the identity tapdoor, identity nullifier, identity secret and identity commitment (serialization done with `rln::utils::fr_to_bytes_le`)
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
    /// let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) = deserialize_identity_tuple(buffer.into_inner());
    /// ```
    pub fn seeded_extended_key_gen<R: Read, W: Write>(
        &self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<()> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;

        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            extended_seeded_keygen(&serialized);
        output_data.write_all(&fr_to_bytes_le(&identity_trapdoor))?;
        output_data.write_all(&fr_to_bytes_le(&identity_nullifier))?;
        output_data.write_all(&fr_to_bytes_le(&identity_secret_hash))?;
        output_data.write_all(&fr_to_bytes_le(&id_commitment))?;

        Ok(())
    }

    /// Recovers the identity secret from two set of proof values computed for same secret in same epoch.
    ///
    /// Input values are:
    /// - `input_proof_data_1`: a reader for the serialization of a RLN zkSNARK proof concatenated with a serialization of the circuit output values and -optionally- the signal information, i.e. either `[ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]` or `[ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> | signal_len<8> | signal<var> ]` (to maintain compatibility with both output of [`generate_rln_proof`](crate::public::RLN::generate_rln_proof) and input of [`verify_rln_proof`](crate::public::RLN::verify_rln_proof))
    /// - `input_proof_data_2`: same as `input_proof_data_1`
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the recovered identity secret hash field element if correctly recovered (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le)), a writer receiving an empty byte vector if not.
    ///
    /// Example
    /// ```
    /// // identity_secret_hash, proof_data_1 and proof_data_2 are computed as in the example code snippet provided for rln::public::RLN::generate_rln_proof using same identity secret and epoch (but not necessarily same signal)
    ///
    /// let mut input_proof_data_1 = Cursor::new(proof_data_1);
    /// let mut input_proof_data_2 = Cursor::new(proof_data_2);
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.recover_id_secret(
    ///     &mut input_proof_data_1,
    ///     &mut input_proof_data_2,
    ///     &mut output_buffer,
    /// )
    /// .unwrap();
    ///
    /// let serialized_identity_secret_hash = output_buffer.into_inner();
    ///
    /// // We ensure that a non-empty value is written to output_buffer
    /// assert!(!serialized_identity_secret_hash.is_empty());
    ///
    /// // We check if the recovered identity secret hash corresponds to the original one
    /// let (recovered_identity_secret_hash, _) = bytes_le_to_fr(&serialized_identity_secret_hash);
    /// assert_eq!(recovered_identity_secret_hash, identity_secret_hash);
    /// ```
    pub fn recover_id_secret<R: Read, W: Write>(
        &self,
        mut input_proof_data_1: R,
        mut input_proof_data_2: R,
        mut output_data: W,
    ) -> Result<()> {
        // We deserialize the two proofs and we get the corresponding RLNProofValues objects
        let mut serialized: Vec<u8> = Vec::new();
        input_proof_data_1.read_to_end(&mut serialized)?;
        // We skip deserialization of the zk-proof at the beginning
        let (proof_values_1, _) = deserialize_proof_values(&serialized[128..]);
        let external_nullifier_1 =
            utils_poseidon_hash(&[proof_values_1.epoch, proof_values_1.rln_identifier]);

        let mut serialized: Vec<u8> = Vec::new();
        input_proof_data_2.read_to_end(&mut serialized)?;
        // We skip deserialization of the zk-proof at the beginning
        let (proof_values_2, _) = deserialize_proof_values(&serialized[128..]);
        let external_nullifier_2 =
            utils_poseidon_hash(&[proof_values_2.epoch, proof_values_2.rln_identifier]);

        // We continue only if the proof values are for the same epoch
        // The idea is that proof values that go as input to this function are verified first (with zk-proof verify), hence ensuring validity of epoch and other fields.
        // Only in case all fields are valid, an external_nullifier for the message will be stored (otherwise signal/proof will be simply discarded)
        // If the nullifier matches one already seen, we can recovery of identity secret.
        if external_nullifier_1 == external_nullifier_2 {
            // We extract the two shares
            let share1 = (proof_values_1.x, proof_values_1.y);
            let share2 = (proof_values_2.x, proof_values_2.y);

            // We recover the secret
            let recovered_identity_secret_hash =
                compute_id_secret(share1, share2, external_nullifier_1);

            // If an identity secret hash is recovered, we write it to output_data, otherwise nothing will be written.
            if let Ok(identity_secret_hash) = recovered_identity_secret_hash {
                output_data.write_all(&fr_to_bytes_le(&identity_secret_hash))?;
            }
        }

        Ok(())
    }

    /// Returns the serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) populated from the identity secret, the Merkle tree index, the epoch and signal.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of `[ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]`
    ///
    /// The function returns the corresponding [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object serialized using [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness)).
    pub fn get_serialized_rln_witness<R: Read>(&mut self, mut input_data: R) -> Result<Vec<u8>> {
        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut witness_byte)?;
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut self.tree, &witness_byte)?;

        serialize_witness(&rln_witness)
    }

    /// Converts a byte serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object to the corresponding JSON serialization.
    ///
    /// Input values are:
    /// - `serialized_witness`: the byte serialization of a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object (serialization done with  [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness)).
    ///
    /// The function returns the corresponding JSON encoding of the input [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object.
    pub fn get_rln_witness_json(&mut self, serialized_witness: &[u8]) -> Result<serde_json::Value> {
        let (rln_witness, _) = deserialize_witness(serialized_witness)?;
        get_json_inputs(&rln_witness)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for RLN<'_> {
    fn default() -> Self {
        let tree_height = TEST_TREE_HEIGHT;
        let buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        Self::new(tree_height, buffer).unwrap()
    }
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
/// hash(&mut input_buffer, &mut output_buffer)
///     .unwrap();
///
/// // We deserialize the keygen output
/// let field_element = deserialize_field_element(output_buffer.into_inner());
/// ```
pub fn hash<R: Read, W: Write>(mut input_data: R, mut output_data: W) -> Result<()> {
    let mut serialized: Vec<u8> = Vec::new();
    input_data.read_to_end(&mut serialized)?;

    let hash = hash_to_field(&serialized);
    output_data.write_all(&fr_to_bytes_le(&hash))?;

    Ok(())
}

/// Hashes a set of elements to a single element in the working prime field, using Poseidon.
///
/// The result is computed as the Poseidon Hash of the input signal.
///
/// Input values are:
/// - `input_data`: a reader for the byte vector containing the input signal.
///
/// Output values are:
/// - `output_data`: a writer receiving the serialization of the resulting field element (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le))
///
/// Example
/// ```
/// let data = vec![hash_to_field(b"foo")];
/// let signal = vec_fr_to_bytes_le(&data);
///
/// let mut input_buffer = Cursor::new(&signal);
/// let mut output_buffer = Cursor::new(Vec::<u8>::new());
/// poseidon_hash(&mut input_buffer, &mut output_buffer)
///     .unwrap();
///
/// // We deserialize the hash output
/// let hash_result = deserialize_field_element(output_buffer.into_inner());
/// ```
pub fn poseidon_hash<R: Read, W: Write>(mut input_data: R, mut output_data: W) -> Result<()> {
    let mut serialized: Vec<u8> = Vec::new();
    input_data.read_to_end(&mut serialized)?;

    let (inputs, _) = bytes_le_to_vec_fr(&serialized)?;
    let hash = utils_poseidon_hash(inputs.as_ref());
    output_data.write_all(&fr_to_bytes_le(&hash))?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
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
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

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
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
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
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch_with_init, _) = bytes_le_to_fr(&buffer.into_inner());

        // `init_tree_with_leaves` resets the tree to the height it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[0..set_index]).unwrap());
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We add the remaining n leaves in a batch starting from index m
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[set_index..]).unwrap());
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

    #[allow(unused_must_use)]
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
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // Get root of empty tree
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
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
    fn test_groth16_proof() {
        let tree_height = TEST_TREE_HEIGHT;

        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // Note: we only test Groth16 proof generation, so we ignore setting the tree in the RLN object
        let rln_witness = random_rln_witness(tree_height);
        let proof_values = proof_values_from_witness(&rln_witness);

        // We compute a Groth16 proof
        let mut input_buffer = Cursor::new(serialize_witness(&rln_witness).unwrap());
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.prove(&mut input_buffer, &mut output_buffer).unwrap();
        let serialized_proof = output_buffer.into_inner();

        // Before checking public verify API, we check that the (deserialized) proof generated by prove is actually valid
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized_proof)).unwrap();
        let verified = verify_proof(&rln.verification_key, &proof, &proof_values);
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
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = rln.tree.leaves_set();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut normalize_usize(identity_index));
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut normalize_usize(signal.len()));
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
        proof_data.append(&mut normalize_usize(signal.len()));
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
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = rln.tree.leaves_set();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut normalize_usize(identity_index));
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut normalize_usize(signal.len()));
        serialized.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(serialized);

        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_buffer.read_to_end(&mut witness_byte).unwrap();
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut rln.tree, &witness_byte).unwrap();

        let serialized_witness = serialize_witness(&rln_witness).unwrap();

        // Calculate witness outside zerokit (simulating what JS is doing)
        let inputs = inputs_for_witness_calculation(&rln_witness)
            .unwrap()
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
            .map(|v| to_bigint(&v).unwrap())
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
        proof_data.append(&mut normalize_usize(signal.len()));
        proof_data.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(proof_data);
        let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();

        assert!(verified);
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
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = rln.tree.leaves_set();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut normalize_usize(identity_index));
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut normalize_usize(signal.len()));
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
        proof_data.append(&mut normalize_usize(signal.len()));
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

    #[test]
    fn test_recover_id_secret() {
        let tree_height = TEST_TREE_HEIGHT;

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = rln.tree.leaves_set();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate two random signals
        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();

        let signal2: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We generate two proofs using same epoch but different signals.

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized1: Vec<u8> = Vec::new();
        serialized1.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized1.append(&mut normalize_usize(identity_index));
        serialized1.append(&mut fr_to_bytes_le(&epoch));

        // The first part is the same for both proof input, so we clone
        let mut serialized2 = serialized1.clone();

        // We attach the first signal to the first proof input
        serialized1.append(&mut normalize_usize(signal1.len()));
        serialized1.append(&mut signal1.to_vec());

        // We attach the second signal to the first proof input
        serialized2.append(&mut normalize_usize(signal2.len()));
        serialized2.append(&mut signal2.to_vec());

        // We generate the first proof
        let mut input_buffer = Cursor::new(serialized1);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let proof_data_1 = output_buffer.into_inner();

        // We generate the second proof
        let mut input_buffer = Cursor::new(serialized2);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let proof_data_2 = output_buffer.into_inner();

        let mut input_proof_data_1 = Cursor::new(proof_data_1.clone());
        let mut input_proof_data_2 = Cursor::new(proof_data_2);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.recover_id_secret(
            &mut input_proof_data_1,
            &mut input_proof_data_2,
            &mut output_buffer,
        )
        .unwrap();

        let serialized_identity_secret_hash = output_buffer.into_inner();

        // We ensure that a non-empty value is written to output_buffer
        assert!(!serialized_identity_secret_hash.is_empty());

        // We check if the recovered identity secret hash corresponds to the original one
        let (recovered_identity_secret_hash, _) = bytes_le_to_fr(&serialized_identity_secret_hash);
        assert_eq!(recovered_identity_secret_hash, identity_secret_hash);

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = keygen();

        // We add it to the tree
        let identity_index_new = rln.tree.leaves_set();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment_new));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signals
        let signal3: [u8; 32] = rng.gen();

        // We prepare proof input. Note that epoch is the same as before
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized3: Vec<u8> = Vec::new();
        serialized3.append(&mut fr_to_bytes_le(&identity_secret_hash_new));
        serialized3.append(&mut normalize_usize(identity_index_new));
        serialized3.append(&mut fr_to_bytes_le(&epoch));
        serialized3.append(&mut normalize_usize(signal3.len()));
        serialized3.append(&mut signal3.to_vec());

        // We generate the proof
        let mut input_buffer = Cursor::new(serialized3);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let proof_data_3 = output_buffer.into_inner();

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let mut input_proof_data_1 = Cursor::new(proof_data_1.clone());
        let mut input_proof_data_3 = Cursor::new(proof_data_3);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.recover_id_secret(
            &mut input_proof_data_1,
            &mut input_proof_data_3,
            &mut output_buffer,
        )
        .unwrap();

        let serialized_identity_secret_hash = output_buffer.into_inner();

        // We ensure that an empty value was written to output_buffer, i.e. no secret is recovered
        assert!(serialized_identity_secret_hash.is_empty());
    }
}
