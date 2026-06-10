#![cfg(feature = "pmtree-ft")]

use std::{fmt::Debug, path::PathBuf, str::FromStr};

use bon::bon;
use serde_json::Value;
use tempfile::Builder;
use zerokit_utils::{
    merkle_tree::{
        validate_override_range_inputs, EmptyIndicesPolicy, FromConfigError, ZerokitMerkleProof,
        ZerokitMerkleTree, ZerokitMerkleTreeError,
    },
    pm_tree::{
        pmtree,
        pmtree::{tree::Key, Database, Hasher, PmtreeErrorKind, TreeErrorKind},
        Config, Mode, SledDB,
    },
};

use crate::{
    circuit::Fr,
    hashers::{poseidon_hash, PoseidonHash},
    utils::{bytes_le_to_fr, fr_to_bytes_le},
};

const METADATA_KEY: [u8; 8] = *b"metadata";

pub struct PmTree {
    tree: pmtree::MerkleTree<SledDB, PoseidonHash>,
    /// The indices of leaves which are set into zero upto next_index.
    /// Set to 0 if the leaf is empty and set to 1 in otherwise.
    cached_leaves_indices: Vec<u8>,
    // metadata that an application may use to store additional information
    metadata: Vec<u8>,
}

pub struct PmTreeProof {
    proof: pmtree::tree::MerkleProof<PoseidonHash>,
}

pub type FrOf<H> = <H as Hasher>::Fr;

// The pmtree Hasher trait used by pmtree Merkle tree
impl Hasher for PoseidonHash {
    type Fr = Fr;

    fn serialize(value: Self::Fr) -> pmtree::Value {
        fr_to_bytes_le(&value)
    }

    fn deserialize(value: pmtree::Value) -> Self::Fr {
        // TODO: add error type to handle deserialization instead of panicking
        let (fr, _) = bytes_le_to_fr(&value).expect("Fr deserialization must be valid");
        fr
    }

    fn default_leaf() -> Self::Fr {
        Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        // TODO: change to hash_pair for this trait to use poseidon_hash_pair for PoseidonHash
        poseidon_hash(inputs)
    }
}

const DEFAULT_TEMPORARY: bool = true;
const DEFAULT_CACHE_CAPACITY: u64 = 1073741824; // 1 Gigabyte
const DEFAULT_FLUSH_EVERY_MS: u64 = 500; // 500 Milliseconds
const DEFAULT_MODE: Mode = Mode::HighThroughput;
const DEFAULT_USE_COMPRESSION: bool = false;

#[derive(Debug, Clone)]
pub struct PmTreeConfig {
    path: PathBuf,
    temporary: bool,
    cache_capacity: u64,
    flush_every_ms: u64,
    mode: Mode,
    use_compression: bool,
    tree_depth: Option<usize>,
}

fn default_tmp_path() -> Result<PathBuf, std::io::Error> {
    Ok(Builder::new()
        .prefix("pmtree-")
        .tempfile()?
        .into_temp_path()
        .to_path_buf())
}

fn resolve_path(temporary: bool, path: Option<PathBuf>) -> Result<PathBuf, FromConfigError> {
    match (temporary, path) {
        (true, None) => Ok(default_tmp_path()?),
        (false, None) => Err(FromConfigError::MissingPath),
        (true, Some(path)) if path.exists() => Err(FromConfigError::PathExists),
        (_, Some(path)) => Ok(path),
    }
}

#[bon]
impl PmTreeConfig {
    #[allow(clippy::new_ret_no_self)]
    #[builder(start_fn = new, finish_fn = build)]
    pub fn create(
        tree_depth: Option<usize>,
        #[builder(into)] path: Option<PathBuf>,
        #[builder(default = DEFAULT_TEMPORARY)] temporary: bool,
        #[builder(default = DEFAULT_CACHE_CAPACITY)] cache_capacity: u64,
        #[builder(default = DEFAULT_FLUSH_EVERY_MS)] flush_every_ms: u64,
        #[builder(default = DEFAULT_MODE)] mode: Mode,
        #[builder(default = DEFAULT_USE_COMPRESSION)] use_compression: bool,
    ) -> Result<Self, FromConfigError> {
        let path = resolve_path(temporary, path)?;
        Ok(Self {
            tree_depth,
            path,
            temporary,
            cache_capacity,
            flush_every_ms,
            mode,
            use_compression,
        })
    }
}

impl PmTreeConfig {
    fn to_sled_config(&self) -> Config {
        Config::new()
            .temporary(self.temporary)
            .path(self.path.clone())
            .cache_capacity(self.cache_capacity)
            .flush_every_ms(Some(self.flush_every_ms))
            .mode(self.mode)
            .use_compression(self.use_compression)
    }
}

impl FromStr for PmTreeConfig {
    type Err = FromConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: Value = serde_json::from_str(s)?;

        let path = config["path"].as_str().map(PathBuf::from);
        let temporary = config["temporary"].as_bool().unwrap_or(DEFAULT_TEMPORARY);
        let cache_capacity = config["cache_capacity"]
            .as_u64()
            .unwrap_or(DEFAULT_CACHE_CAPACITY);
        let flush_every_ms = config["flush_every_ms"]
            .as_u64()
            .unwrap_or(DEFAULT_FLUSH_EVERY_MS);
        let mode = match config["mode"].as_str() {
            Some("LowSpace") => Mode::LowSpace,
            _ => DEFAULT_MODE,
        };
        let use_compression = config["use_compression"]
            .as_bool()
            .unwrap_or(DEFAULT_USE_COMPRESSION);

        let tree_depth = config["tree_depth"].as_u64().map(|depth| depth as usize);

        let path = resolve_path(temporary, path)?;
        Ok(Self {
            path,
            temporary,
            cache_capacity,
            flush_every_ms,
            mode,
            use_compression,
            tree_depth,
        })
    }
}

impl Default for PmTreeConfig {
    fn default() -> Self {
        PmTreeConfig::new()
            .build()
            .expect("Default PmtreeConfig must be valid")
    }
}

impl ZerokitMerkleTree for PmTree {
    type Proof = PmTreeProof;
    type Hasher = PoseidonHash;
    type Config = PmTreeConfig;

    fn default(depth: usize) -> Result<Self, ZerokitMerkleTreeError> {
        let default_config = PmTreeConfig::default();
        PmTree::new(depth, Self::Hasher::default_leaf(), default_config)
    }

    fn new(
        depth: usize,
        _default_leaf: FrOf<Self::Hasher>,
        config: Self::Config,
    ) -> Result<Self, ZerokitMerkleTreeError> {
        if let Some(config_depth) = config.tree_depth {
            if config_depth != depth {
                return Err(ZerokitMerkleTreeError::InvalidDepth);
            }
        }
        let sled_config = config.to_sled_config();
        let tree_loaded = pmtree::MerkleTree::load(sled_config.clone());
        let tree = match tree_loaded {
            Ok(tree) => {
                if tree.depth() != depth {
                    return Err(ZerokitMerkleTreeError::InvalidDepth);
                }
                tree
            }
            Err(_) => pmtree::MerkleTree::new(depth, sled_config)?,
        };

        let capacity = 1usize.checked_shl(depth as u32).ok_or({
            ZerokitMerkleTreeError::PmtreeErrorKind(PmtreeErrorKind::TreeError(
                TreeErrorKind::IndexOutOfBounds,
            ))
        })?;

        let mut cached_leaves_indices = vec![0u8; capacity];
        let default_leaf = Self::Hasher::default_leaf();
        for (index, cached) in cached_leaves_indices
            .iter_mut()
            .enumerate()
            .take(tree.leaves_set())
        {
            if tree.get(index)? != default_leaf {
                *cached = 1;
            }
        }

        Ok(PmTree {
            tree,
            cached_leaves_indices,
            metadata: Vec::new(),
        })
    }

    fn depth(&self) -> usize {
        self.tree.depth()
    }

    fn capacity(&self) -> usize {
        self.tree.capacity()
    }

    fn leaves_set(&self) -> usize {
        self.tree.leaves_set()
    }

    fn root(&self) -> FrOf<Self::Hasher> {
        self.tree.root()
    }

    fn set(
        &mut self,
        index: usize,
        leaf: FrOf<Self::Hasher>,
    ) -> Result<(), ZerokitMerkleTreeError> {
        self.tree.set(index, leaf)?;
        self.cached_leaves_indices[index] = 1;
        Ok(())
    }

    fn set_range<I: IntoIterator<Item = FrOf<Self::Hasher>>>(
        &mut self,
        start: usize,
        values: I,
    ) -> Result<(), ZerokitMerkleTreeError> {
        let v = values.into_iter().collect::<Vec<_>>();
        self.tree.set_range(start, v.clone())?;
        for i in start..start + v.len() {
            self.cached_leaves_indices[i] = 1
        }
        Ok(())
    }

    fn get(&self, index: usize) -> Result<FrOf<Self::Hasher>, ZerokitMerkleTreeError> {
        self.tree
            .get(index)
            .map_err(ZerokitMerkleTreeError::PmtreeErrorKind)
    }

    fn get_subtree_root(
        &self,
        n: usize,
        index: usize,
    ) -> Result<FrOf<Self::Hasher>, ZerokitMerkleTreeError> {
        if n > self.depth() {
            return Err(ZerokitMerkleTreeError::InvalidLevel);
        }
        if index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::InvalidLeaf);
        }
        if n == 0 {
            Ok(self.root())
        } else if n == self.depth() {
            self.get(index)
        } else {
            match self.tree.get_elem(Key::new(n, index >> (self.depth() - n))) {
                Ok(value) => Ok(value),
                Err(_) => Err(ZerokitMerkleTreeError::InvalidSubTreeIndex),
            }
        }
    }

    fn get_empty_leaves_indices(&self) -> Vec<usize> {
        let next_idx = self.leaves_set();
        self.cached_leaves_indices
            .iter()
            .take(next_idx)
            .enumerate()
            .filter(|&(_, &v)| v == 0u8)
            .map(|(idx, _)| idx)
            .collect()
    }

    fn override_range<I: IntoIterator<Item = FrOf<Self::Hasher>>, J: IntoIterator<Item = usize>>(
        &mut self,
        start: usize,
        leaves: I,
        indices: J,
    ) -> Result<(), ZerokitMerkleTreeError> {
        let leaves = leaves.into_iter().collect::<Vec<_>>();
        let validated = validate_override_range_inputs(
            start,
            leaves.len(),
            indices.into_iter().collect::<Vec<_>>(),
            self.capacity(),
            // PMTree supports set-only overrides (`indices` can be empty).
            EmptyIndicesPolicy::Allow,
        )?;
        let indices = validated.indices;

        match (leaves.len(), indices.len()) {
            (0, 0) => Err(ZerokitMerkleTreeError::InvalidLeaf),
            (1, 0) => self.set(start, leaves[0]),
            (0, 1) => self.delete(indices[0]),
            (_, 0) => self.set_range(start, leaves.into_iter()),
            (0, _) => self
                .remove_indices(&indices)
                .map_err(ZerokitMerkleTreeError::PmtreeErrorKind),
            (_, _) => self
                .remove_indices_and_set_leaves(
                    start,
                    leaves,
                    &indices,
                    validated
                        .max_index
                        .ok_or(ZerokitMerkleTreeError::InvalidIndices)?,
                )
                .map_err(ZerokitMerkleTreeError::PmtreeErrorKind),
        }
    }

    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<(), ZerokitMerkleTreeError> {
        let index = self.tree.leaves_set();
        self.tree.update_next(leaf)?;
        self.cached_leaves_indices[index] = 1;
        Ok(())
    }

    /// Delete a leaf in the merkle tree given its index
    ///
    /// Deleting a leaf is done by resetting it to its default value. Note that the next_index field
    /// will not be changed (== previously used index cannot be reused - this to avoid replay
    /// attacks or unexpected and very hard to tackle issues)
    fn delete(&mut self, index: usize) -> Result<(), ZerokitMerkleTreeError> {
        self.tree.delete(index)?;
        self.cached_leaves_indices[index] = 0;
        Ok(())
    }

    fn proof(&self, index: usize) -> Result<Self::Proof, ZerokitMerkleTreeError> {
        let proof = self.tree.proof(index)?;
        Ok(PmTreeProof { proof })
    }

    fn verify(
        &self,
        leaf: &FrOf<Self::Hasher>,
        merkle_proof: &Self::Proof,
    ) -> Result<bool, ZerokitMerkleTreeError> {
        if self.tree.verify(leaf, &merkle_proof.proof) {
            Ok(true)
        } else {
            Err(ZerokitMerkleTreeError::InvalidMerkleProof)
        }
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), ZerokitMerkleTreeError> {
        self.tree.db.put(METADATA_KEY, metadata.to_vec())?;
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>, ZerokitMerkleTreeError> {
        if !self.metadata.is_empty() {
            return Ok(self.metadata.clone());
        }
        // if empty, try searching the db
        let data = self.tree.db.get(METADATA_KEY)?;

        // Return empty metadata if not found, otherwise return the data
        Ok(data.unwrap_or_default())
    }

    fn close_db_connection(&mut self) -> Result<(), ZerokitMerkleTreeError> {
        self.tree
            .db
            .close()
            .map_err(ZerokitMerkleTreeError::PmtreeErrorKind)
    }
}

type PmTreeHasher = <PmTree as ZerokitMerkleTree>::Hasher;
type FrOfPmTreeHasher = FrOf<PmTreeHasher>;

impl PmTree {
    fn remove_indices(&mut self, indices: &[usize]) -> Result<(), PmtreeErrorKind> {
        if indices.is_empty() {
            return Err(PmtreeErrorKind::TreeError(
                pmtree::TreeErrorKind::InvalidKey,
            ));
        }
        let start = indices[0];
        let end = indices[indices.len() - 1] + 1;

        let new_leaves = (start..end).map(|_| PmTreeHasher::default_leaf());

        self.tree.set_range(start, new_leaves)?;

        for i in start..end {
            self.cached_leaves_indices[i] = 0
        }
        Ok(())
    }

    fn remove_indices_and_set_leaves(
        &mut self,
        start: usize,
        leaves: Vec<FrOfPmTreeHasher>,
        indices: &[usize],
        max_index: usize,
    ) -> Result<(), PmtreeErrorKind> {
        if indices.is_empty() {
            return Err(PmtreeErrorKind::TreeError(
                pmtree::TreeErrorKind::InvalidKey,
            ));
        }
        let min_index = indices[0];
        if min_index >= max_index || min_index > start {
            return Err(PmtreeErrorKind::TreeError(
                pmtree::TreeErrorKind::IndexOutOfBounds,
            ));
        }

        let mut set_values = vec![PmTreeHasher::default_leaf(); max_index - min_index];

        for i in min_index..start {
            if !indices.contains(&i) {
                let value = self.tree.get(i)?;
                set_values[i - min_index] = value;
            }
        }

        for (i, &leaf) in leaves.iter().enumerate() {
            set_values[start - min_index + i] = leaf;
        }

        self.tree.set_range(start, set_values)?;

        for i in indices {
            self.cached_leaves_indices[*i] = 0;
        }

        for i in start..(max_index - min_index) {
            self.cached_leaves_indices[i] = 1
        }
        Ok(())
    }
}

impl ZerokitMerkleProof for PmTreeProof {
    type Index = u8;
    type Hasher = PoseidonHash;

    fn length(&self) -> usize {
        self.proof.length()
    }

    fn leaf_index(&self) -> usize {
        self.proof.leaf_index()
    }

    fn get_path_elements(&self) -> Vec<FrOf<Self::Hasher>> {
        self.proof.get_path_elements()
    }

    fn get_path_index(&self) -> Vec<Self::Index> {
        self.proof.get_path_index()
    }

    fn compute_root_from(&self, leaf: &FrOf<Self::Hasher>) -> FrOf<Self::Hasher> {
        self.proof.compute_root_from(leaf)
    }
}
