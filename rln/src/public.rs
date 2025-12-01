// This crate is the main public API for RLN module.
// It is used by the FFI, WASM and should be used by tests as well

#[cfg(target_arch = "wasm32")]
use num_bigint::BigInt;
#[cfg(not(feature = "stateless"))]
use {
    crate::poseidon_tree::PoseidonTree,
    std::str::FromStr,
    utils::error::ZerokitMerkleTreeError,
    utils::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree},
};

#[cfg(target_arch = "wasm32")]
use crate::protocol::generate_proof_with_witness;
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    circuit::{graph_from_folder, zkey_from_folder},
    protocol::generate_proof,
};
use crate::{
    circuit::{zkey_from_raw, Fr, Proof, Zkey},
    error::{RLNError, VerifyError},
    protocol::{proof_values_from_witness, verify_proof, RLNProofValues, RLNWitnessInput},
};

/// The application-specific RLN identifier.
///
/// Prevents a RLN ZK proof generated for one application to be re-used in another one.
pub const RLN_IDENTIFIER: &[u8] = b"zerokit/rln/010203040506070809";

/// This trait allows accepting different config input types for tree configuration.
#[cfg(not(feature = "stateless"))]
pub trait TreeConfigInput {
    /// Convert the input to a tree configuration struct.
    fn into_tree_config(self) -> Result<<PoseidonTree as ZerokitMerkleTree>::Config, RLNError>;
}

/// Implementation for string slices containing JSON configuration
#[cfg(not(feature = "stateless"))]
impl TreeConfigInput for &str {
    fn into_tree_config(self) -> Result<<PoseidonTree as ZerokitMerkleTree>::Config, RLNError> {
        if self.is_empty() {
            Ok(<PoseidonTree as ZerokitMerkleTree>::Config::default())
        } else {
            Ok(<PoseidonTree as ZerokitMerkleTree>::Config::from_str(self)?)
        }
    }
}

/// Implementation for Option<T> where T implements TreeConfigInput.
#[cfg(not(feature = "stateless"))]
impl<T: TreeConfigInput> TreeConfigInput for Option<T> {
    fn into_tree_config(self) -> Result<<PoseidonTree as ZerokitMerkleTree>::Config, RLNError> {
        match self {
            Some(config) => config.into_tree_config(),
            None => Ok(<PoseidonTree as ZerokitMerkleTree>::Config::default()),
        }
    }
}

/// Implementation for direct builder pattern Config struct
#[cfg(feature = "pmtree-ft")]
impl TreeConfigInput for <PoseidonTree as ZerokitMerkleTree>::Config {
    fn into_tree_config(self) -> Result<<PoseidonTree as ZerokitMerkleTree>::Config, RLNError> {
        Ok(self)
    }
}

/// The RLN object.
///
/// It implements the methods required to update the internal Merkle Tree, generate and verify RLN ZK proofs.
pub struct RLN {
    pub(crate) zkey: Zkey,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    pub(crate) tree: PoseidonTree,
}

impl RLN {
    /// Creates a new RLN object by loading circuit resources from a folder.
    ///
    /// - `tree_depth`: the depth of the internal Merkle tree
    /// - `tree_config`: configuration for the Merkle tree (accepts multiple types via TreeConfigInput trait)
    ///
    /// The `tree_config` parameter accepts:
    /// - JSON string: `"{\"path\": \"/database\"}"`
    /// - Empty string for defaults: `""`
    /// - Direct config (with pmtree feature): `PmtreeConfig::builder().path("/database").build()?`
    /// - Option: `Some(config)` or `None` for defaults
    ///
    /// Examples:
    /// ```
    /// // Using default config
    /// let rln = RLN::new(20, "").unwrap();
    ///
    /// // Using JSON string
    /// let config_json = r#"{"path": "/database", "cache_capacity": 1073741824}"#;
    /// let rln = RLN::new(20, config_json).unwrap();
    ///
    /// // Using None for defaults
    /// let rln = RLN::new(20, None::<String>).unwrap();
    /// ```
    ///
    /// For advanced usage with builder pattern (pmtree feature):
    /// ```
    /// let config = PmtreeConfig::builder()
    ///     .path("/database")
    ///     .cache_capacity(1073741824)
    ///     .mode(Mode::HighThroughput)
    ///     .build()?;
    ///
    /// let rln = RLN::new(20, config)?;
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), not(feature = "stateless")))]
    pub fn new<T: TreeConfigInput>(tree_depth: usize, tree_config: T) -> Result<RLN, RLNError> {
        let zkey = zkey_from_folder().to_owned();
        let graph_data = graph_from_folder().to_owned();
        let config = tree_config.into_tree_config()?;

        // We compute a default empty tree
        let tree = PoseidonTree::new(
            tree_depth,
            <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
            config,
        )?;

        Ok(RLN {
            zkey,
            graph_data,
            #[cfg(not(feature = "stateless"))]
            tree,
        })
    }

    /// Creates a new stateless RLN object by loading circuit resources from a folder.
    ///
    /// Example:
    /// ```
    /// // We create a new RLN instance
    /// let mut rln = RLN::new();
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), feature = "stateless"))]
    pub fn new() -> Result<RLN, RLNError> {
        let zkey = zkey_from_folder().to_owned();
        let graph_data = graph_from_folder().to_owned();

        Ok(RLN { zkey, graph_data })
    }

    /// Creates a new RLN object by passing circuit resources as byte vectors.
    ///
    /// Input parameters are:
    /// - `tree_depth`: the depth of the internal Merkle tree
    /// - `zkey_data`: a byte vector containing the proving key (`rln_final.arkzkey`) as binary file
    /// - `graph_data`: a byte vector containing the graph data (`graph.bin`) as binary file
    /// - `tree_config`: configuration for the Merkle tree (accepts multiple types via TreeConfigInput trait)
    ///
    /// Examples:
    /// ```
    /// let tree_depth = 20;
    /// let resources_folder = "./resources/tree_depth_20/";
    ///
    /// let mut resources: Vec<Vec<u8>> = Vec::new();
    /// for filename in ["rln_final.arkzkey", "graph.bin"] {
    ///     let fullpath = format!("{resources_folder}{filename}");
    ///     let mut file = File::open(&fullpath).expect("no file found");
    ///     let metadata = std::fs::metadata(&fullpath).expect("unable to read metadata");
    ///     let mut buffer = vec![0; metadata.len() as usize];
    ///     file.read_exact(&mut buffer).expect("buffer overflow");
    ///     resources.push(buffer);
    /// }
    ///
    /// // Using default config
    /// let rln = RLN::new_with_params(tree_depth, resources[0].clone(), resources[1].clone(), "").unwrap();
    ///
    /// // Using JSON config
    /// let config_json = r#"{"path": "/database"}"#;
    /// let rln = RLN::new_with_params(tree_depth, resources[0].clone(), resources[1].clone(), config_json).unwrap();
    ///
    /// // Using builder pattern (with pmtree feature)
    /// let config = PmtreeConfig::builder().path("/database").build()?;
    /// let rln = RLN::new_with_params(tree_depth, resources[0].clone(), resources[1].clone(), config)?;
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), not(feature = "stateless")))]
    pub fn new_with_params<T: TreeConfigInput>(
        tree_depth: usize,
        zkey_data: Vec<u8>,
        graph_data: Vec<u8>,
        tree_config: T,
    ) -> Result<RLN, RLNError> {
        let zkey = zkey_from_raw(&zkey_data)?;
        let config = tree_config.into_tree_config()?;

        // We compute a default empty tree
        let tree = PoseidonTree::new(
            tree_depth,
            <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
            config,
        )?;

        Ok(RLN {
            zkey,
            graph_data,
            #[cfg(not(feature = "stateless"))]
            tree,
        })
    }

    /// Creates a new stateless RLN object by passing circuit resources as byte vectors.
    ///
    /// Input parameters are:
    /// - `zkey_data`: a byte vector containing to the proving key (`rln_final.arkzkey`) as binary file
    /// - `graph_data`: a byte vector containing the graph data (`graph.bin`) as binary file
    ///
    /// Example:
    /// ```
    /// let resources_folder = "./resources/tree_depth_20/";
    ///
    /// let mut resources: Vec<Vec<u8>> = Vec::new();
    /// for filename in ["rln_final.arkzkey", "graph.bin"] {
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
    /// )?;
    /// ```
    #[cfg(all(not(target_arch = "wasm32"), feature = "stateless"))]
    pub fn new_with_params(zkey_data: Vec<u8>, graph_data: Vec<u8>) -> Result<RLN, RLNError> {
        let zkey = zkey_from_raw(&zkey_data)?;

        Ok(RLN { zkey, graph_data })
    }

    /// Creates a new stateless RLN object by passing circuit resources as a byte vector.
    ///
    /// Input parameters are:
    /// - `zkey_data`: a byte vector containing the proving key (`rln_final.arkzkey`) as binary file
    ///
    /// Example:
    /// ```
    /// let zkey_path = "./resources/tree_depth_20/rln_final.arkzkey";
    ///
    /// let mut file = File::open(zkey_path).expect("Failed to open file");
    /// let metadata = std::fs::metadata(zkey_path).expect("Failed to read metadata");
    /// let mut zkey_data = vec![0; metadata.len() as usize];
    /// file.read_exact(&mut zkey_data).expect("Failed to read file");
    ///
    /// let mut rln = RLN::new_with_params(zkey_data)?;
    /// ```
    #[cfg(all(target_arch = "wasm32", feature = "stateless"))]
    pub fn new_with_params(zkey_data: Vec<u8>) -> Result<RLN, RLNError> {
        let zkey = zkey_from_raw(&zkey_data)?;

        Ok(RLN { zkey })
    }

    // Merkle-tree APIs

    /// Initializes the internal Merkle tree.
    ///
    /// Leaves are set to the default value implemented in PoseidonTree implementation.
    #[cfg(not(feature = "stateless"))]
    pub fn set_tree(&mut self, tree_depth: usize) -> Result<(), RLNError> {
        // We compute a default empty tree of desired depth
        self.tree = PoseidonTree::default(tree_depth)?;

        Ok(())
    }

    /// Sets a leaf value at position index in the internal Merkle tree.
    ///
    /// Example:
    /// ```
    /// // We generate a random identity secret hash and commitment pair
    /// let (identity_secret, id_commitment) = keygen();
    ///
    /// // We define the tree index where rate_commitment will be added
    /// let id_index = 10;
    /// let user_message_limit = 1;
    ///
    /// let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
    ///
    /// // Set the leaf directly
    /// rln.set_leaf(id_index, rate_commitment).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_leaf(&mut self, index: usize, leaf: Fr) -> Result<(), RLNError> {
        self.tree.set(index, leaf)?;
        Ok(())
    }

    /// Gets a leaf value at position index in the internal Merkle tree.
    ///
    /// Example:
    /// ```
    /// let id_index = 10;
    /// let rate_commitment = rln.get_leaf(id_index).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_leaf(&self, index: usize) -> Result<Fr, RLNError> {
        let leaf = self.tree.get(index)?;
        Ok(leaf)
    }

    /// Sets multiple leaves starting from position index in the internal Merkle tree.
    ///
    /// If n leaves are passed as input, these will be set at positions `index`, `index+1`, ..., `index+n-1` respectively.
    ///
    /// This function updates the internal Merkle tree `next_index` value indicating the next available index corresponding to a never-set leaf as `next_index = max(next_index, index + n)`.
    ///
    /// Example:
    /// ```
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
    /// rln.set_leaves_from(index, leaves).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_leaves_from(&mut self, index: usize, leaves: Vec<Fr>) -> Result<(), RLNError> {
        self.tree
            .override_range(index, leaves.into_iter(), [].into_iter())?;
        Ok(())
    }

    /// Resets the tree state to default and sets multiple leaves starting from index 0.
    ///
    /// In contrast to [`set_leaves_from`](crate::public::RLN::set_leaves_from), this function resets to 0 the internal `next_index` value, before setting the input leaves values.
    #[cfg(not(feature = "stateless"))]
    pub fn init_tree_with_leaves(&mut self, leaves: Vec<Fr>) -> Result<(), RLNError> {
        // NOTE: this requires the tree to be initialized with the correct depth initially
        // TODO: accept tree_depth as a parameter and initialize the tree with that depth
        self.set_tree(self.tree.depth())?;
        self.set_leaves_from(0, leaves)
    }

    /// Sets multiple leaves starting from position index in the internal Merkle tree.
    /// Also accepts an array of indices to remove from the tree.
    ///
    /// If n leaves are passed as input, these will be set at positions `index`, `index+1`, ..., `index+n-1` respectively.
    /// If m indices are passed as input, these will be removed from the tree.
    ///
    /// This function updates the internal Merkle tree `next_index` value indicating the next available index corresponding to a never-set leaf as `next_index = max(next_index, index + n)`.
    ///
    /// Example:
    /// ```
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
    /// let mut indices: Vec<usize> = Vec::new();
    /// for i in 0..no_of_leaves {
    ///    if i % 2 == 0 {
    ///       indices.push(i);
    ///   }
    /// }
    ///
    /// // We atomically add leaves and remove indices from the tree
    /// rln.atomic_operation(index, leaves, indices).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn atomic_operation(
        &mut self,
        index: usize,
        leaves: Vec<Fr>,
        indices: Vec<usize>,
    ) -> Result<(), RLNError> {
        self.tree
            .override_range(index, leaves.into_iter(), indices.into_iter())?;
        Ok(())
    }

    /// Returns the number of leaves that have been set in the internal Merkle tree.
    #[cfg(not(feature = "stateless"))]
    pub fn leaves_set(&self) -> usize {
        self.tree.leaves_set()
    }

    /// Sets a leaf value at the next available never-set leaf index.
    ///
    /// This function updates the internal Merkle tree `next_index` value indicating the next available index corresponding to a never-set leaf as `next_index = next_index + 1`.
    ///
    /// Example:
    /// ```
    /// let tree_depth = 20;
    /// let start_index = 10;
    /// let no_of_leaves = 256;
    ///
    /// // We reset the tree
    /// rln.set_tree(tree_depth).unwrap();
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
    /// rln.set_leaves_from(index, leaves).unwrap();
    ///
    /// // We set 256 leaves starting from index 10: next_index value is now max(0, 256+10) = 266
    ///
    /// // We set a leaf on next available index
    /// // rate_commitment will be set at index 266
    /// let (_, id_commitment) = keygen();
    /// let rate_commitment = poseidon_hash(&[id_commitment, 1.into()]);
    /// rln.set_next_leaf(rate_commitment).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn set_next_leaf(&mut self, leaf: Fr) -> Result<(), RLNError> {
        self.tree.update_next(leaf)?;
        Ok(())
    }

    /// Sets the value of the leaf at position index to the hardcoded default value.
    ///
    /// This function does not change the internal Merkle tree `next_index` value.
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
    ///
    /// This metadata is not used by the RLN module.
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
    /// Example
    ///
    /// ```
    /// let metadata = rln.get_metadata().unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_metadata(&self) -> Result<Vec<u8>, RLNError> {
        let metadata = self.tree.metadata()?;
        Ok(metadata)
    }

    /// Returns the Merkle tree root
    ///
    /// Example
    /// ```
    /// let root = rln.get_root();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_root(&self) -> Fr {
        self.tree.root()
    }

    /// Returns the root of subtree in the Merkle tree
    ///
    /// Example
    /// ```
    /// let level = 1;
    /// let index = 2;
    /// let subroot = rln.get_subtree_root(level, index).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_subtree_root(&self, level: usize, index: usize) -> Result<Fr, RLNError> {
        let subroot = self.tree.get_subtree_root(level, index)?;
        Ok(subroot)
    }

    /// Returns the Merkle proof of the leaf at position index
    ///
    /// Example
    /// ```
    /// let index = 10;
    /// let (path_elements, identity_path_index) = rln.get_proof(index).unwrap();
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_proof(&self, index: usize) -> Result<(Vec<Fr>, Vec<u8>), RLNError> {
        let merkle_proof = self.tree.proof(index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        Ok((path_elements, identity_path_index))
    }

    /// Returns indices of leaves in the tree are set to zero (upto the final leaf that was set).
    ///
    /// Example
    /// ```
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
    /// rln.set_leaves_from(index, leaves).unwrap();
    ///
    /// // Get indices of first empty leaves upto start_index
    /// let idxs = rln.get_empty_leaves_indices();
    /// assert_eq!(idxs, [0, 1, 2, 3, 4]);
    /// ```
    #[cfg(not(feature = "stateless"))]
    pub fn get_empty_leaves_indices(&self) -> Vec<usize> {
        self.tree.get_empty_leaves_indices()
    }

    /// Closes the connection to the Merkle tree database.
    ///
    /// This function should be called before the RLN object is dropped.
    /// If not called, the connection will be closed when the RLN object is dropped.
    #[cfg(not(feature = "stateless"))]
    pub fn flush(&mut self) -> Result<(), ZerokitMerkleTreeError> {
        self.tree.close_db_connection()
    }

    // zkSNARK APIs

    /// Computes a zkSNARK RLN proof using a [`RLNWitnessInput`](crate::protocol::RLNWitnessInput) object.
    ///
    /// Example:
    /// ```
    /// let witness = random_rln_witness(tree_depth);
    /// let proof_values = proof_values_from_witness(&witness);
    ///
    /// // We compute a Groth16 proof
    /// let zk_proof = rln.generate_proof(&witness).unwrap();
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate_proof(&self, witness: &RLNWitnessInput) -> Result<Proof, RLNError> {
        let proof = generate_proof(&self.zkey, witness, &self.graph_data)?;
        Ok(proof)
    }

    /// Verifies a zkSNARK RLN proof.
    ///
    /// Example:
    /// ```
    /// let witness = random_rln_witness(tree_depth);
    ///
    /// // We compute a Groth16 proof
    /// let zk_proof = rln.prove(&witness).unwrap();
    ///
    /// // We compute proof values directly from witness
    /// let proof_values = proof_values_from_witness(&witness);
    ///
    /// // We verify the Groth16 proof against the provided zk-proof and proof values
    /// let verified = rln.verify(&zk_proof, &proof_values).unwrap();
    ///
    /// assert!(verified);
    /// ```
    pub fn verify(&self, proof: &Proof, proof_values: &RLNProofValues) -> Result<bool, RLNError> {
        let verified = verify_proof(&self.zkey.0.vk, proof, proof_values)?;
        Ok(verified)
    }

    /// Verifies a zkSNARK RLN proof with x coordinate check (stateful - checks internal tree root).
    #[cfg(not(feature = "stateless"))]
    pub fn verify_rln_proof(
        &self,
        proof: &Proof,
        proof_values: &RLNProofValues,
        x: &Fr,
    ) -> Result<bool, RLNError> {
        let verified = verify_proof(&self.zkey.0.vk, proof, proof_values)?;
        if !verified {
            return Err(VerifyError::InvalidProof.into());
        }

        if self.tree.root() != proof_values.root {
            return Err(VerifyError::InvalidRoot.into());
        }

        if *x != proof_values.x {
            return Err(VerifyError::InvalidSignal.into());
        }

        Ok(true)
    }

    /// Verifies a zkSNARK RLN proof against provided roots with x coordinate check.
    ///
    /// If the roots slice is empty, root verification is skipped.
    pub fn verify_with_roots(
        &self,
        proof: &Proof,
        proof_values: &RLNProofValues,
        x: &Fr,
        roots: &[Fr],
    ) -> Result<bool, RLNError> {
        let verified = verify_proof(&self.zkey.0.vk, proof, proof_values)?;
        if !verified {
            return Err(VerifyError::InvalidProof.into());
        }

        if !roots.is_empty() && !roots.contains(&proof_values.root) {
            return Err(VerifyError::InvalidRoot.into());
        }

        if *x != proof_values.x {
            return Err(VerifyError::InvalidSignal.into());
        }

        Ok(true)
    }

    /// Generate RLN Proof using a witness and returns both proof and proof values.
    ///
    /// This is a convenience method that combines proof generation and proof values extraction.
    /// For WASM usage with pre-calculated witness from witness calculator.
    ///
    /// Example:
    /// ```
    /// let witness = RLNWitnessInput::new(...);
    /// let (proof, proof_values) = rln.generate_rln_proof(&witness).unwrap();
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate_rln_proof(
        &self,
        witness: &RLNWitnessInput,
    ) -> Result<(Proof, RLNProofValues), RLNError> {
        let proof_values = proof_values_from_witness(witness)?;
        let proof = generate_proof(&self.zkey, witness, &self.graph_data)?;
        Ok((proof, proof_values))
    }

    /// Generate RLN Proof using a pre-calculated witness from witness calculator (WASM).
    ///
    /// This is used when the witness has been calculated externally using a witness calculator.
    #[cfg(target_arch = "wasm32")]
    pub fn generate_rln_proof_with_witness(
        &self,
        calculated_witness: Vec<BigInt>,
        witness: &RLNWitnessInput,
    ) -> Result<(Proof, RLNProofValues), RLNError> {
        let proof_values = proof_values_from_witness(witness)?;
        let proof = generate_proof_with_witness(calculated_witness, &self.zkey)?;
        Ok((proof, proof_values))
    }
}
