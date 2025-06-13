use crate::circuit::{zkey_from_raw, Curve, Fr};
use crate::hashers::{hash_to_field, poseidon_hash as utils_poseidon_hash};
use crate::protocol::{
    compute_id_secret, deserialize_proof_values, deserialize_witness, extended_keygen,
    extended_seeded_keygen, generate_proof, keygen, proof_inputs_to_rln_witness,
    proof_values_from_witness, rln_witness_to_bigint_json, rln_witness_to_json, seeded_keygen,
    serialize_proof_values, serialize_witness, verify_proof,
};
use crate::utils::{
    bytes_le_to_fr, bytes_le_to_vec_fr, bytes_le_to_vec_u8, fr_byte_size, fr_to_bytes_le,
    vec_fr_to_bytes_le, vec_u8_to_bytes_le,
};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::circuit::{graph_from_folder, zkey_from_folder},
    std::default::Default,
};

#[cfg(target_arch = "wasm32")]
use crate::protocol::generate_proof_with_witness;

/// This is the main public API for RLN module. It is used by the FFI, and should be
/// used by tests etc. as well
#[cfg(not(feature = "stateless"))]
use {
    crate::{circuit::TEST_TREE_HEIGHT, poseidon_tree::PoseidonTree},
    serde_json::{json, Value},
    std::str::FromStr,
    utils::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree},
};

use crate::error::{ConversionError, ProtocolError, RLNError};
use ark_groth16::{Proof as ArkProof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
#[cfg(target_arch = "wasm32")]
use num_bigint::BigInt;
use std::io::Cursor;
use utils::error::ZerokitMerkleTreeError;
use zeroize::Zeroize;

/// The application-specific RLN identifier.
///
/// Prevents a RLN ZK proof generated for one application to be re-used in another one.
pub const RLN_IDENTIFIER: &[u8] = b"zerokit/rln/010203040506070809";

/// The RLN object.
///
/// It implements the methods required to update the internal Merkle Tree, generate and verify RLN ZK proofs.
///
/// I/O is mostly done using writers and readers implementing `std::io::Write` and `std::io::Read`, respectively.
pub struct RLN {
    proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
    pub(crate) verification_key: VerifyingKey<Curve>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    pub(crate) tree: PoseidonTree,
}

impl RLN {
    /// Creates a new RLN object by loading circuit resources from a folder.
    ///
    /// Input parameters are
    /// - `tree_height`: the height of the internal Merkle tree
    /// - `input_data`: include `tree_config` a reader for a string containing a json with the merkle tree configuration
    ///
    /// Example:
    /// ```
    /// use std::io::Cursor;
    ///
    /// let tree_height = 20;
    /// let input = Cursor::new(json!({}).to_string());
    ///
    /// // We create a new RLN instance
    /// let mut rln = RLN::new(tree_height, input);
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), not(feature = "stateless")))]
    pub fn new<R: Read>(tree_height: usize, mut input_data: R) -> Result<RLN, RLNError> {
        // We read input
        let mut input: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input)?;

        let rln_config: Value = serde_json::from_str(&String::from_utf8(input)?)?;
        let tree_config = rln_config["tree_config"].to_string();

        let proving_key = zkey_from_folder().to_owned();
        let verification_key = proving_key.0.vk.to_owned();
        let graph_data = graph_from_folder().to_owned();

        let tree_config: <PoseidonTree as ZerokitMerkleTree>::Config = if tree_config.is_empty() {
            <PoseidonTree as ZerokitMerkleTree>::Config::default()
        } else {
            <PoseidonTree as ZerokitMerkleTree>::Config::from_str(&tree_config)?
        };

        // We compute a default empty tree
        let tree = PoseidonTree::new(
            tree_height,
            <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
            tree_config,
        )?;

        Ok(RLN {
            proving_key,
            verification_key,
            graph_data,
            #[cfg(not(feature = "stateless"))]
            tree,
        })
    }

    /// Creates a new stateless RLN object by loading circuit resources from a folder.
    ///
    /// Example:
    ///
    /// ```
    /// // We create a new RLN instance
    /// let mut rln = RLN::new();
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), feature = "stateless"))]
    pub fn new() -> Result<RLN, RLNError> {
        let proving_key = zkey_from_folder().to_owned();
        let verification_key = proving_key.0.vk.to_owned();
        let graph_data = graph_from_folder().to_owned();

        Ok(RLN {
            proving_key,
            verification_key,
            graph_data,
        })
    }

    /// Creates a new RLN object by passing circuit resources as byte vectors.
    ///
    /// Input parameters are
    /// - `tree_height`: the height of the internal Merkle tree
    /// - `zkey_vec`: a byte vector containing to the proving key (`rln_final.zkey`)  or (`rln_final.arkzkey`) as binary file
    /// - `graph_data`: a byte vector containing the graph data (`graph.bin`) as binary file
    /// - `tree_config_input`: a reader for a string containing a json with the merkle tree configuration
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
    /// for filename in ["rln_final.zkey", "graph.bin"] {
    ///     let fullpath = format!("{resources_folder}{filename}");
    ///     let mut file = File::open(&fullpath).expect("no file found");
    ///     let metadata = std::fs::metadata(&fullpath).expect("unable to read metadata");
    ///     let mut buffer = vec![0; metadata.len() as usize];
    ///     file.read_exact(&mut buffer).expect("buffer overflow");
    ///     resources.push(buffer);
    /// }
    ///
    /// let tree_config = "".to_string();
    /// let tree_config_buffer = &Buffer::from(tree_config.as_bytes());
    ///
    /// let mut rln = RLN::new_with_params(
    ///     tree_height,
    ///     resources[0].clone(),
    ///     resources[1].clone(),
    ///     tree_config_buffer,
    /// );
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), not(feature = "stateless")))]
    pub fn new_with_params<R: Read>(
        tree_height: usize,
        zkey_vec: Vec<u8>,
        graph_data: Vec<u8>,
        mut tree_config_input: R,
    ) -> Result<RLN, RLNError> {
        let proving_key = zkey_from_raw(&zkey_vec)?;
        let verification_key = proving_key.0.vk.to_owned();

        let mut tree_config_vec: Vec<u8> = Vec::new();
        tree_config_input.read_to_end(&mut tree_config_vec)?;
        let tree_config_str = String::from_utf8(tree_config_vec)?;
        let tree_config: <PoseidonTree as ZerokitMerkleTree>::Config = if tree_config_str.is_empty()
        {
            <PoseidonTree as ZerokitMerkleTree>::Config::default()
        } else {
            <PoseidonTree as ZerokitMerkleTree>::Config::from_str(&tree_config_str)?
        };

        // We compute a default empty tree
        let tree = PoseidonTree::new(
            tree_height,
            <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
            tree_config,
        )?;

        Ok(RLN {
            proving_key,
            verification_key,
            graph_data,
            #[cfg(not(feature = "stateless"))]
            tree,
        })
    }

    /// Creates a new stateless RLN object by passing circuit resources as byte vectors.
    ///
    /// Input parameters are
    /// - `zkey_vec`: a byte vector containing to the proving key (`rln_final.zkey`)  or (`rln_final.arkzkey`) as binary file
    /// - `graph_data`: a byte vector containing the graph data (`graph.bin`) as binary file
    ///
    /// Example:
    /// ```
    /// use std::fs::File;
    /// use std::io::Read;
    ///
    /// let resources_folder = "./resources/tree_height_20/";
    ///
    /// let mut resources: Vec<Vec<u8>> = Vec::new();
    /// for filename in ["rln_final.zkey", "graph.bin"] {
    ///     let fullpath = format!("{resources_folder}{filename}");
    ///     let mut file = File::open(&fullpath).expect("no file found");
    ///     let metadata = std::fs::metadata(&fullpath).expect("unable to read metadata");
    ///     let mut buffer = vec![0; metadata.len() as usize];
    ///     file.read_exact(&mut buffer).expect("buffer overflow");
    ///     resources.push(buffer);
    /// }
    ///
    /// let mut rln = RLN::new_with_params(
    ///     resources[0].clone(),
    ///     resources[1].clone(),
    /// );
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), feature = "stateless"))]
    pub fn new_with_params(zkey_vec: Vec<u8>, graph_data: Vec<u8>) -> Result<RLN, RLNError> {
        let proving_key = zkey_from_raw(&zkey_vec)?;
        let verification_key = proving_key.0.vk.to_owned();

        Ok(RLN {
            proving_key,
            verification_key,
            graph_data,
        })
    }

    /// Creates a new stateless RLN object by passing circuit resources as a byte vector.
    ///
    /// Input parameters are
    /// - `zkey_vec`: a byte vector containing the proving key (`rln_final.zkey`) or (`rln_final.arkzkey`) as binary file
    ///
    /// Example:
    /// ```
    /// use std::fs::File;
    /// use std::io::Read;
    ///
    /// let zkey_path = "./resources/tree_height_20/rln_final.zkey";
    ///
    /// let mut file = File::open(zkey_path).expect("Failed to open file");
    /// let metadata = std::fs::metadata(zkey_path).expect("Failed to read metadata");
    /// let mut zkey_vec = vec![0; metadata.len() as usize];
    /// file.read_exact(&mut zkey_vec).expect("Failed to read file");
    ///
    /// let mut rln = RLN::new_with_params(zkey_vec)?;
    /// ```
    #[cfg(all(target_arch = "wasm32", feature = "stateless"))]
    pub fn new_with_params(zkey_vec: Vec<u8>) -> Result<RLN, RLNError> {
        let proving_key = zkey_from_raw(&zkey_vec)?;
        let verification_key = proving_key.0.vk.to_owned();

        Ok(RLN {
            proving_key,
            verification_key,
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
    #[cfg(not(feature = "stateless"))]
    pub fn set_tree(&mut self, tree_height: usize) -> Result<(), RLNError> {
        // We compute a default empty tree of desired height
        self.tree = PoseidonTree::default(tree_height)?;

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
    /// // We define the tree index where rate_commitment will be added
    /// let id_index = 10;
    /// let user_message_limit = 1;
    ///
    /// let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
    ///
    /// // We serialize rate_commitment and pass it to set_leaf
    /// let mut buffer = Cursor::new(serialize_field_element(rate_commitment));
    /// rln.set_leaf(id_index, &mut buffer).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_leaf<R: Read>(&mut self, index: usize, mut input_data: R) -> Result<(), RLNError> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte)?;

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_fr(&leaf_byte);
        self.tree.set(index, leaf)?;

        Ok(())
    }

    /// Gets a leaf value at position index in the internal Merkle tree.
    /// The leaf value is written to output_data.
    /// Input values are:
    /// - `index`: the index of the leaf
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the metadata
    ///
    /// Example:
    /// ```
    /// use crate::protocol::*;
    /// use std::io::Cursor;
    ///
    /// let id_index = 10;
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.get_leaf(id_index, &mut buffer).unwrap();
    /// let rate_commitment = deserialize_field_element(&buffer.into_inner()).unwrap();
    #[cfg(not(feature = "stateless"))]
    pub fn get_leaf<W: Write>(&self, index: usize, mut output_data: W) -> Result<(), RLNError> {
        // We get the leaf at input index
        let leaf = self.tree.get(index)?;

        // We serialize the leaf and write it to output
        let leaf_byte = fr_to_bytes_le(&leaf);
        output_data.write_all(&leaf_byte)?;

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
    ///     let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    ///     leaves.push(rate_commitment);
    /// }
    ///
    /// // We add leaves in a batch into the tree
    /// let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
    /// rln.set_leaves_from(index, &mut buffer).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_leaves_from<R: Read>(
        &mut self,
        index: usize,
        mut input_data: R,
    ) -> Result<(), RLNError> {
        // We read input
        let mut leaves_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaves_byte)?;

        let (leaves, _) = bytes_le_to_vec_fr(&leaves_byte)?;

        // We set the leaves
        self.tree
            .override_range(index, leaves.into_iter(), [].into_iter())?;
        Ok(())
    }

    /// Resets the tree state to default and sets multiple leaves starting from index 0.
    ///
    /// In contrast to [`set_leaves_from`](crate::public::RLN::set_leaves_from), this function resets to 0 the internal `next_index` value, before setting the input leaves values.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of multiple leaf values (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le))
    #[cfg(not(feature = "stateless"))]
    pub fn init_tree_with_leaves<R: Read>(&mut self, input_data: R) -> Result<(), RLNError> {
        // reset the tree
        // NOTE: this requires the tree to be initialized with the correct height initially
        // TODO: accept tree_height as a parameter and initialize the tree with that height
        self.set_tree(self.tree.depth())?;
        self.set_leaves_from(0, input_data)
    }

    /// Sets multiple leaves starting from position index in the internal Merkle tree.
    /// Also accepts an array of indices to remove from the tree.
    ///
    /// If n leaves are passed as input, these will be set at positions `index`, `index+1`, ..., `index+n-1` respectively.
    /// If m indices are passed as input, these will be removed from the tree.
    ///
    /// This function updates the internal Merkle tree `next_index value indicating the next available index corresponding to a never-set leaf as `next_index = max(next_index, index + n)`.
    ///
    /// Input values are:
    /// - `index`: the index of the first leaf to be set
    /// - `input_leaves`: a reader for the serialization of multiple leaf values (serialization done with [`rln::utils::vec_fr_to_bytes_le`](crate::utils::vec_fr_to_bytes_le))
    /// - `input_indices`: a reader for the serialization of multiple indices to remove (serialization done with [`rln::utils::vec_u8_to_bytes_le`](crate::utils::vec_u8_to_bytes_le))
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
    ///     let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    ///     leaves.push(rate_commitment);
    /// }
    ///
    /// let mut indices: Vec<u8> = Vec::new();
    /// for i in 0..no_of_leaves {
    ///    if i % 2 == 0 {
    ///       indices.push(i as u8);
    ///   }
    /// }
    ///
    /// // We atomically add leaves and remove indices from the tree
    /// let mut leaves_buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
    /// let mut indices_buffer = Cursor::new(vec_u8_to_bytes_le(&indices));
    /// rln.atomic_operation(index, &mut leaves_buffer, indices_buffer).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn atomic_operation<R: Read>(
        &mut self,
        index: usize,
        mut input_leaves: R,
        mut input_indices: R,
    ) -> Result<(), RLNError> {
        // We read input
        let mut leaves_byte: Vec<u8> = Vec::new();
        input_leaves.read_to_end(&mut leaves_byte)?;

        let (leaves, _) = bytes_le_to_vec_fr(&leaves_byte)?;

        let mut indices_byte: Vec<u8> = Vec::new();
        input_indices.read_to_end(&mut indices_byte)?;

        let (indices, _) = bytes_le_to_vec_u8(&indices_byte)?;
        let indices: Vec<usize> = indices.iter().map(|x| *x as usize).collect();

        // We set the leaves
        self.tree
            .override_range(index, leaves.into_iter(), indices.into_iter())?;
        Ok(())
    }

    #[cfg(not(feature = "stateless"))]
    pub fn leaves_set(&mut self) -> usize {
        self.tree.leaves_set()
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
    ///     let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    ///     leaves.push(rate_commitment);
    /// }
    ///
    /// // We add leaves in a batch into the tree
    /// let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
    /// rln.set_leaves_from(index, &mut buffer).unwrap();
    ///
    /// // We set 256 leaves starting from index 10: next_index value is now max(0, 256+10) = 266
    ///
    /// // We set a leaf on next available index
    /// // rate_commitment will be set at index 266
    /// let (_, id_commitment) = keygen();
    /// let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    /// let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
    /// rln.set_next_leaf(&mut buffer).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_next_leaf<R: Read>(&mut self, mut input_data: R) -> Result<(), RLNError> {
        // We read input
        let mut leaf_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut leaf_byte)?;

        // We set the leaf at input index
        let (leaf, _) = bytes_le_to_fr(&leaf_byte);
        self.tree.update_next(leaf)?;

        Ok(())
    }

    /// Sets the value of the leaf at position index to the hardcoded default value.
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
    #[cfg(not(feature = "stateless"))]
    pub fn delete_leaf(&mut self, index: usize) -> Result<(), RLNError> {
        self.tree.delete(index)?;
        Ok(())
    }

    /// Sets some metadata that a consuming application may want to store in the RLN object.
    /// This metadata is not used by the RLN module.
    ///
    /// Input values are:
    /// - `metadata`: a byte vector containing the metadata
    ///
    /// Example
    ///
    /// ```
    /// let metadata = b"some metadata";
    /// rln.set_metadata(metadata).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), RLNError> {
        self.tree.set_metadata(metadata)?;
        Ok(())
    }

    /// Returns the metadata stored in the RLN object.
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the metadata
    ///
    /// Example
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.get_metadata(&mut buffer).unwrap();
    /// let metadata = buffer.into_inner();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_metadata<W: Write>(&self, mut output_data: W) -> Result<(), RLNError> {
        let metadata = self.tree.metadata()?;
        output_data.write_all(&metadata)?;
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
    #[cfg(not(feature = "stateless"))]
    pub fn get_root<W: Write>(&self, mut output_data: W) -> Result<(), RLNError> {
        let root = self.tree.root();
        output_data.write_all(&fr_to_bytes_le(&root))?;
        Ok(())
    }

    /// Returns the root of subtree in the Merkle tree
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the node value (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le))
    ///
    /// Example
    /// ```
    /// use rln::utils::*;
    ///
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// let level = 1;
    /// let index = 2;
    /// rln.get_subtree_root(level, index, &mut buffer).unwrap();
    /// let (subroot, _) = bytes_le_to_fr(&buffer.into_inner());
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_subtree_root<W: Write>(
        &self,
        level: usize,
        index: usize,
        mut output_data: W,
    ) -> Result<(), RLNError> {
        let subroot = self.tree.get_subtree_root(level, index)?;
        output_data.write_all(&fr_to_bytes_le(&subroot))?;

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
    #[cfg(not(feature = "stateless"))]
    pub fn get_proof<W: Write>(&self, index: usize, mut output_data: W) -> Result<(), RLNError> {
        let merkle_proof = self.tree.proof(index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        // Note: unwrap safe - vec_fr_to_bytes_le & vec_u8_to_bytes_le are infallible
        output_data.write_all(&vec_fr_to_bytes_le(&path_elements))?;
        output_data.write_all(&vec_u8_to_bytes_le(&identity_path_index))?;

        Ok(())
    }

    /// Returns indices of leaves in the tree are set to zero (upto the final leaf that was set).
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the indices of leaves.
    ///
    /// Example
    /// ```
    /// use rln::circuit::Fr;
    /// use rln::utils::*;
    ///
    /// let start_index = 5;
    /// let no_of_leaves = 256;
    ///
    /// // We generate a vector of random leaves
    /// let mut leaves: Vec<Fr> = Vec::new();
    /// let mut rng = thread_rng();
    /// for _ in 0..no_of_leaves {
    ///     let (_, id_commitment) = keygen();
    ///     let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    ///     leaves.push(rate_commitment);
    /// }
    ///
    /// // We add leaves in a batch into the tree
    /// let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
    /// rln.set_leaves_from(index, &mut buffer).unwrap();
    ///
    /// // Get indices of first empty leaves upto start_index
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.get_empty_leaves_indices(&mut buffer).unwrap();
    /// let idxs = bytes_le_to_vec_usize(&buffer.into_inner()).unwrap();
    /// assert_eq!(idxs, [0, 1, 2, 3, 4]);
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_empty_leaves_indices<W: Write>(&self, mut output_data: W) -> Result<(), RLNError> {
        let idxs = self.tree.get_empty_leaves_indices();
        idxs.serialize_compressed(&mut output_data)?;
        Ok(())
    }

    ////////////////////////////////////////////////////////
    // zkSNARK APIs
    ////////////////////////////////////////////////////////
    /// Computes a zkSNARK RLN proof using a [`RLNWitnessInput`].
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of a [`RLNWitnessInput`] object, containing the public and private inputs to the ZK circuits (serialization done using [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness))
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
    ) -> Result<(), RLNError> {
        // We read input RLN witness and we serialize_compressed it
        let mut serialized_witness: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized_witness)?;
        let (rln_witness, _) = deserialize_witness(&serialized_witness)?;

        let proof = generate_proof(&self.proving_key, &rln_witness, &self.graph_data)?;

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        proof.serialize_compressed(&mut output_data)?;

        Ok(())
    }

    /// Verifies a zkSNARK RLN proof.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of the RLN zkSNARK proof concatenated with a serialization of the circuit output values,
    ///   i.e. `[ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]`, where <_> indicates the byte length.
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
    pub fn verify<R: Read>(&self, mut input_data: R) -> Result<bool, RLNError> {
        // Input data is serialized for Curve as:
        // serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes), i.e.
        // [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let mut input_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut input_byte)?;
        let proof = ArkProof::deserialize_compressed(&mut Cursor::new(&input_byte[..128]))?;

        let (proof_values, _) = deserialize_proof_values(&input_byte[128..]);

        let verified = verify_proof(&self.verification_key, &proof, &proof_values)?;

        Ok(verified)
    }

    /// Computes a zkSNARK RLN proof from the identity secret, the Merkle tree index, the user message limit, the message id, the external nullifier (which include epoch and rln identifier) and signal.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of `[ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]`
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the zkSNARK proof and the circuit evaluations outputs, i.e. `[ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]`
    ///
    /// Example
    /// ```
    /// use rln::protocol::*:
    /// use rln::utils::*;
    /// use rln::hashers::*;
    ///
    /// // Generate identity pair
    /// let (identity_secret_hash, id_commitment) = keygen();
    ///
    /// // We set as leaf rate_commitment after storing its index
    /// let identity_index = 10;
    /// let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    /// let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
    /// rln.set_leaf(identity_index, &mut buffer).unwrap();
    ///
    /// // We generate a random epoch
    /// let epoch = hash_to_field(b"test-epoch");
    /// // We generate a random rln_identifier
    /// let rln_identifier = hash_to_field(b"test-rln-identifier");
    /// // We generate a external nullifier
    /// let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
    /// // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
    /// let message_id = Fr::from(1);
    ///
    /// // We prepare input for generate_rln_proof API
    /// // input_data is [ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
    /// let prove_input = prepare_prove_input(
    ///     identity_secret_hash,
    ///     identity_index,
    ///     user_message_limit,
    ///     message_id,
    ///     external_nullifier,
    ///     &signal,
    /// );
    ///
    /// let mut input_buffer = Cursor::new(serialized);
    /// let mut output_buffer = Cursor::new(Vec::<u8>::new());
    /// rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
    ///     .unwrap();
    ///
    /// // proof_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
    /// let mut proof_data = output_buffer.into_inner();
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), not(feature = "stateless")))]
    pub fn generate_rln_proof<R: Read, W: Write>(
        &mut self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<(), RLNError> {
        // We read input RLN witness and we serialize_compressed it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut witness_byte)?;
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut self.tree, &witness_byte)?;
        let proof_values = proof_values_from_witness(&rln_witness)?;

        let proof = generate_proof(&self.proving_key, &rln_witness, &self.graph_data)?;

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize_compressed(&mut output_data)?;
        output_data.write_all(&serialize_proof_values(&proof_values))?;

        Ok(())
    }

    /// Generate RLN Proof using a witness calculated from outside zerokit
    ///
    /// output_data is  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate_rln_proof_with_witness<R: Read, W: Write>(
        &mut self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<(), RLNError> {
        let mut serialized_witness: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized_witness)?;
        let (rln_witness, _) = deserialize_witness(&serialized_witness)?;
        let proof_values = proof_values_from_witness(&rln_witness)?;

        let proof = generate_proof(&self.proving_key, &rln_witness, &self.graph_data)?;

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize_compressed(&mut output_data)?;
        output_data.write_all(&serialize_proof_values(&proof_values))?;
        Ok(())
    }

    /// Generate RLN Proof using a witness calculated from outside zerokit
    ///
    /// output_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
    #[cfg(target_arch = "wasm32")]
    pub fn generate_rln_proof_with_witness<W: Write>(
        &mut self,
        calculated_witness: Vec<BigInt>,
        serialized_witness: Vec<u8>,
        mut output_data: W,
    ) -> Result<(), RLNError> {
        let (rln_witness, _) = deserialize_witness(&serialized_witness[..])?;
        let proof_values = proof_values_from_witness(&rln_witness)?;

        let proof = generate_proof_with_witness(calculated_witness, &self.proving_key).unwrap();

        // Note: we export a serialization of ark-groth16::Proof not semaphore::Proof
        // This proof is compressed, i.e. 128 bytes long
        proof.serialize_compressed(&mut output_data)?;
        output_data.write_all(&serialize_proof_values(&proof_values))?;
        Ok(())
    }

    /// Verifies a zkSNARK RLN proof against the provided proof values and the state of the internal Merkle tree.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of the RLN zkSNARK proof concatenated with a serialization of the circuit output values and the signal information,
    ///   i.e. `[ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var>]`, where <_> indicates the byte length.
    ///
    /// The function returns true if the zkSNARK proof is valid with respect to the provided circuit output values and signal. Returns false otherwise.
    ///
    /// Note that contrary to [`verify`](crate::public::RLN::verify), this function takes additionally as input the signal and further verifies if
    /// - the Merkle tree root corresponds to the root provided as input;
    /// - the input signal corresponds to the Shamir's x coordinate provided as input
    /// - the hardcoded application [RLN identifier](crate::public::RLN_IDENTIFIER) corresponds to the RLN identifier provided as input
    ///
    /// Example
    /// ```
    /// // proof_data is computed as in the example code snippet provided for rln::public::RLN::generate_rln_proof
    ///
    /// // We prepare input for verify_rln_proof API
    /// // input_data is  `[ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var>]`
    /// // that is [ proof_data || signal_len<8> | signal<var> ]
    /// let verify_input = prepare_verify_input(proof_data, &signal);
    ///
    /// let mut input_buffer = Cursor::new(verify_input);
    /// let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();
    ///
    /// assert!(verified);
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn verify_rln_proof<R: Read>(&self, mut input_data: R) -> Result<bool, RLNError> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof =
            ArkProof::deserialize_compressed(&mut Cursor::new(&serialized[..128].to_vec()))?;
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..]);
        all_read += read;

        let signal_len = usize::try_from(u64::from_le_bytes(
            serialized[all_read..all_read + 8]
                .try_into()
                .map_err(ConversionError::FromSlice)?,
        ))
        .map_err(ConversionError::from)?;
        all_read += 8;

        let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

        let verified = verify_proof(&self.verification_key, &proof, &proof_values)?;
        let x = hash_to_field(&signal);

        // Consistency checks to counter proof tampering
        Ok(verified && (self.tree.root() == proof_values.root) && (x == proof_values.x))
    }

    /// Verifies a zkSNARK RLN proof against the provided proof values and a set of allowed Merkle tree roots.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of the RLN zkSNARK proof concatenated with a serialization of the circuit output values and the signal information, i.e. `[ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var>]`
    /// - `roots_data`: a reader for the serialization of a vector of roots, i.e. `[ number_of_roots<8> | root_1<32> | ... | root_n<32> ]` (number_of_roots is an uint64 in little-endian, roots are serialized using `rln::utils::fr_to_bytes_le`)
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
    ///     .verify_with_roots(&mut input_buffer, &mut roots_buffer)
    ///     .unwrap();
    ///
    /// assert!(verified);
    /// ```
    pub fn verify_with_roots<R: Read>(
        &self,
        mut input_data: R,
        mut roots_data: R,
    ) -> Result<bool, RLNError> {
        let mut serialized: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut serialized)?;
        let mut all_read = 0;
        let proof =
            ArkProof::deserialize_compressed(&mut Cursor::new(&serialized[..128].to_vec()))?;
        all_read += 128;
        let (proof_values, read) = deserialize_proof_values(&serialized[all_read..]);
        all_read += read;

        let signal_len = usize::try_from(u64::from_le_bytes(
            serialized[all_read..all_read + 8]
                .try_into()
                .map_err(ConversionError::FromSlice)?,
        ))
        .map_err(ConversionError::ToUsize)?;
        all_read += 8;

        let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

        let verified = verify_proof(&self.verification_key, &proof, &proof_values)?;

        // First consistency checks to counter proof tampering
        let x = hash_to_field(&signal);
        let partial_result = verified && (x == proof_values.x);

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
    /// // We serialize_compressed the keygen output
    /// let (identity_secret_hash, id_commitment) = deserialize_identity_pair(buffer.into_inner());
    /// ```
    pub fn key_gen<W: Write>(&self, mut output_data: W) -> Result<(), RLNError> {
        let (identity_secret_hash, id_commitment) = keygen();
        let mut identity_secret_hash_: Fr = identity_secret_hash.into();
        output_data.write_all(&fr_to_bytes_le(&identity_secret_hash_))?;
        identity_secret_hash_.zeroize();
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
    /// - `output_data`: a writer receiving the serialization of the identity trapdoor, identity nullifier, identity secret and identity commitment (serialization done with `rln::utils::fr_to_bytes_le`)
    ///
    /// Example
    /// ```
    /// use rln::protocol::*;
    ///
    /// // We generate an identity tuple
    /// let mut buffer = Cursor::new(Vec::<u8>::new());
    /// rln.extended_key_gen(&mut buffer).unwrap();
    ///
    /// // We serialize_compressed the keygen output
    /// let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) = deserialize_identity_tuple(buffer.into_inner());
    /// ```
    pub fn extended_key_gen<W: Write>(&self, mut output_data: W) -> Result<(), RLNError> {
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
    /// // We serialize_compressed the keygen output
    /// let (identity_secret_hash, id_commitment) = deserialize_identity_pair(output_buffer.into_inner());
    /// ```
    pub fn seeded_key_gen<R: Read, W: Write>(
        &self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<(), RLNError> {
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
    /// - `output_data`: a writer receiving the serialization of the identity trapdoor, identity nullifier, identity secret and identity commitment (serialization done with `rln::utils::fr_to_bytes_le`)
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
    /// // We serialize_compressed the keygen output
    /// let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) = deserialize_identity_tuple(buffer.into_inner());
    /// ```
    pub fn seeded_extended_key_gen<R: Read, W: Write>(
        &self,
        mut input_data: R,
        mut output_data: W,
    ) -> Result<(), RLNError> {
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

    /// Recovers the identity secret from two set of proof values computed for same secret in same epoch with same rln identifier.
    ///
    /// Input values are:
    /// - `input_proof_data_1`: a reader for the serialization of a RLN zkSNARK proof concatenated with a serialization of the circuit output values and -optionally- the signal information,
    ///   i.e. either `[proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]`
    ///   or `[ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]` (to maintain compatibility with both output of [`generate_rln_proof`](crate::public::RLN::generate_rln_proof) and input of [`verify_rln_proof`](crate::public::RLN::verify_rln_proof))
    /// - `input_proof_data_2`: same as `input_proof_data_1`
    ///
    /// Output values are:
    /// - `output_data`: a writer receiving the serialization of the recovered identity secret hash field element if correctly recovered (serialization done with [`rln::utils::fr_to_bytes_le`](crate::utils::fr_to_bytes_le)), a writer receiving an empty byte vector if not.
    ///
    /// Example
    /// ```
    /// // identity_secret_hash, proof_data_1 and proof_data_2 are computed as in the example code snippet provided for rln::public::RLN::generate_rln_proof using same identity secret, epoch and rln identifier (but not necessarily same signal)
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
    ) -> Result<(), RLNError> {
        // We serialize_compressed the two proofs, and we get the corresponding RLNProofValues objects
        let mut serialized: Vec<u8> = Vec::new();
        input_proof_data_1.read_to_end(&mut serialized)?;
        // We skip deserialization of the zk-proof at the beginning
        let (proof_values_1, _) = deserialize_proof_values(&serialized[128..]);
        let external_nullifier_1 = proof_values_1.external_nullifier;

        let mut serialized: Vec<u8> = Vec::new();
        input_proof_data_2.read_to_end(&mut serialized)?;
        // We skip deserialization of the zk-proof at the beginning
        let (proof_values_2, _) = deserialize_proof_values(&serialized[128..]);
        let external_nullifier_2 = proof_values_2.external_nullifier;

        // We continue only if the proof values are for the same external nullifier (which includes epoch and rln identifier)
        // The idea is that proof values that go as input to this function are verified first (with zk-proof verify), hence ensuring validity of external nullifier and other fields.
        // Only in case all fields are valid, an external_nullifier for the message will be stored (otherwise signal/proof will be simply discarded)
        // If the nullifier matches one already seen, we can recover of identity secret.
        if external_nullifier_1 == external_nullifier_2 {
            // We extract the two shares
            let share1 = (proof_values_1.x, proof_values_1.y);
            let share2 = (proof_values_2.x, proof_values_2.y);

            // We recover the secret
            let recovered_identity_secret_hash =
                compute_id_secret(share1, share2).map_err(RLNError::RecoverSecret)?;

            // If an identity secret hash is recovered, we write it to output_data, otherwise nothing will be written.
            output_data.write_all(&fr_to_bytes_le(&recovered_identity_secret_hash.into()))?;
        }

        Ok(())
    }

    /// Returns the serialization of a [`RLNWitnessInput`] populated from the identity secret, the Merkle tree index, the user message limit, the message id, the external nullifier (which include epoch and rln identifier) and signal.
    ///
    /// Input values are:
    /// - `input_data`: a reader for the serialization of `[ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]`
    ///
    /// The function returns the corresponding [`RLNWitnessInput`] object serialized using [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness).
    #[cfg(not(feature = "stateless"))]
    pub fn get_serialized_rln_witness<R: Read>(
        &mut self,
        mut input_data: R,
    ) -> Result<Vec<u8>, RLNError> {
        // We read input RLN witness and we serialize_compressed it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_data.read_to_end(&mut witness_byte)?;
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut self.tree, &witness_byte)?;

        serialize_witness(&rln_witness).map_err(RLNError::Protocol)
    }

    /// Converts a byte serialization of a [`RLNWitnessInput`] object to the corresponding JSON serialization.
    ///
    /// Input values are:
    /// - `serialized_witness`: the byte serialization of a [`RLNWitnessInput`] object (serialization done with  [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness)).
    ///
    /// The function returns the corresponding JSON encoding of the input [`RLNWitnessInput`] object.
    pub fn get_rln_witness_json(
        &mut self,
        serialized_witness: &[u8],
    ) -> Result<serde_json::Value, ProtocolError> {
        let (rln_witness, _) = deserialize_witness(serialized_witness)?;
        rln_witness_to_json(&rln_witness)
    }

    /// Converts a byte serialization of a [`RLNWitnessInput`] object to the corresponding JSON serialization.
    /// Before serialization the data will be translated into big int for further calculation in the witness calculator.
    ///
    /// Input values are:
    /// - `serialized_witness`: the byte serialization of a [`RLNWitnessInput`] object (serialization done with  [`rln::protocol::serialize_witness`](crate::protocol::serialize_witness)).
    ///
    /// The function returns the corresponding JSON encoding of the input [`RLNWitnessInput`] object.
    pub fn get_rln_witness_bigint_json(
        &mut self,
        serialized_witness: &[u8],
    ) -> Result<serde_json::Value, ProtocolError> {
        let (rln_witness, _) = deserialize_witness(serialized_witness)?;
        rln_witness_to_bigint_json(&rln_witness)
    }

    /// Closes the connection to the Merkle tree database.
    /// This function should be called before the RLN object is dropped.
    /// If not called, the connection will be closed when the RLN object is dropped.
    /// This improves robustness of the tree.
    #[cfg(not(feature = "stateless"))]
    pub fn flush(&mut self) -> Result<(), ZerokitMerkleTreeError> {
        self.tree.close_db_connection()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for RLN {
    fn default() -> Self {
        #[cfg(not(feature = "stateless"))]
        {
            let tree_height = TEST_TREE_HEIGHT;
            let buffer = Cursor::new(json!({}).to_string());
            Self::new(tree_height, buffer).unwrap()
        }
        #[cfg(feature = "stateless")]
        Self::new().unwrap()
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
/// // We serialize_compressed the keygen output
/// let field_element = deserialize_field_element(output_buffer.into_inner());
/// ```
pub fn hash<R: Read, W: Write>(
    mut input_data: R,
    mut output_data: W,
) -> Result<(), std::io::Error> {
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
/// // We serialize_compressed the hash output
/// let hash_result = deserialize_field_element(output_buffer.into_inner());
/// ```
pub fn poseidon_hash<R: Read, W: Write>(
    mut input_data: R,
    mut output_data: W,
) -> Result<(), RLNError> {
    let mut serialized: Vec<u8> = Vec::new();
    input_data.read_to_end(&mut serialized)?;

    let (inputs, _) = bytes_le_to_vec_fr(&serialized)?;
    let hash = utils_poseidon_hash(inputs.as_ref());
    output_data.write_all(&fr_to_bytes_le(&hash))?;

    Ok(())
}
