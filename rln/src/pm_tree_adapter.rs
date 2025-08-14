use serde_json::Value;
use std::fmt::Debug;
use std::path::PathBuf;
use std::str::FromStr;

use crate::circuit::Fr;
use crate::hashers::{poseidon_hash, PoseidonHash};
use crate::utils::{bytes_le_to_fr, fr_to_bytes_le};
use utils::error::{FromConfigError, ZerokitMerkleTreeError};
use utils::pmtree::tree::Key;
use utils::pmtree::{Database, Hasher, PmtreeErrorKind};
use utils::{pmtree, Config, Mode, SledDB, ZerokitMerkleProof, ZerokitMerkleTree};

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
        let (fr, _) = bytes_le_to_fr(&value);
        fr
    }

    fn default_leaf() -> Self::Fr {
        Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}

fn get_tmp_path() -> PathBuf {
    std::env::temp_dir().join(format!("pmtree-{}", rand::random::<u64>()))
}

fn get_tmp() -> bool {
    true
}

pub struct PmtreeConfig(Config);

pub struct PmtreeConfigBuilder {
    path: Option<PathBuf>,
    temporary: Option<bool>,
    cache_capacity: Option<u64>,
    flush_every_ms: Option<u64>,
    mode: Option<Mode>,
    use_compression: Option<bool>,
}

impl PmtreeConfigBuilder {
    pub fn new() -> Self {
        Self {
            path: None,
            temporary: None,
            cache_capacity: None,
            flush_every_ms: None,
            mode: None,
            use_compression: None,
        }
    }

    pub fn path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn temporary(mut self, temporary: bool) -> Self {
        self.temporary = Some(temporary);
        self
    }

    pub fn cache_capacity(mut self, capacity: u64) -> Self {
        self.cache_capacity = Some(capacity);
        self
    }

    pub fn flush_every_ms(mut self, ms: u64) -> Self {
        self.flush_every_ms = Some(ms);
        self
    }

    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn use_compression(mut self, compression: bool) -> Self {
        self.use_compression = Some(compression);
        self
    }

    pub fn build(self) -> Result<PmtreeConfig, FromConfigError> {
        let path = self.path.unwrap_or_else(get_tmp_path);
        let temporary = self.temporary.unwrap_or_else(get_tmp);

        if temporary && path.exists() {
            return Err(FromConfigError::PathExists);
        }

        let config = Config::new()
            .temporary(temporary)
            .path(path)
            .cache_capacity(self.cache_capacity.unwrap_or(1024 * 1024 * 1024))
            .flush_every_ms(self.flush_every_ms)
            .mode(self.mode.unwrap_or(Mode::HighThroughput))
            .use_compression(self.use_compression.unwrap_or(false));

        Ok(PmtreeConfig(config))
    }
}

impl Default for PmtreeConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PmtreeConfig {
    pub fn builder() -> PmtreeConfigBuilder {
        PmtreeConfigBuilder::new()
    }
}

impl FromStr for PmtreeConfig {
    type Err = FromConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: Value = serde_json::from_str(s)?;

        let path = config["path"].as_str();
        let path = path.map(PathBuf::from);
        let temporary = config["temporary"].as_bool();
        let cache_capacity = config["cache_capacity"].as_u64();
        let flush_every_ms = config["flush_every_ms"].as_u64();
        let mode = match config["mode"].as_str() {
            Some("HighThroughput") => Mode::HighThroughput,
            Some("LowSpace") => Mode::LowSpace,
            _ => Mode::HighThroughput,
        };
        let use_compression = config["use_compression"].as_bool();

        if temporary.is_some()
            && path.is_some()
            && temporary.unwrap()
            && path.as_ref().unwrap().exists()
        {
            return Err(FromConfigError::PathExists);
        }

        let config = Config::new()
            .temporary(temporary.unwrap_or(get_tmp()))
            .path(path.unwrap_or(get_tmp_path()))
            .cache_capacity(cache_capacity.unwrap_or(1024 * 1024 * 1024))
            .flush_every_ms(flush_every_ms)
            .mode(mode)
            .use_compression(use_compression.unwrap_or(false));
        Ok(PmtreeConfig(config))
    }
}

impl Default for PmtreeConfig {
    fn default() -> Self {
        let tmp_path = get_tmp_path();
        PmtreeConfig(
            Config::new()
                .temporary(true)
                .path(tmp_path)
                .cache_capacity(150_000)
                .mode(Mode::HighThroughput)
                .use_compression(false)
                .flush_every_ms(Some(12_000)),
        )
    }
}
impl Debug for PmtreeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Clone for PmtreeConfig {
    fn clone(&self) -> Self {
        PmtreeConfig(self.0.clone())
    }
}

impl ZerokitMerkleTree for PmTree {
    type Proof = PmTreeProof;
    type Hasher = PoseidonHash;
    type Config = PmtreeConfig;

    fn default(depth: usize) -> Result<Self, ZerokitMerkleTreeError> {
        let default_config = PmtreeConfig::default();
        PmTree::new(depth, Self::Hasher::default_leaf(), default_config)
    }

    fn new(
        depth: usize,
        _default_leaf: FrOf<Self::Hasher>,
        config: Self::Config,
    ) -> Result<Self, ZerokitMerkleTreeError> {
        let tree_loaded = pmtree::MerkleTree::load(config.clone().0);
        let tree = match tree_loaded {
            Ok(tree) => tree,
            Err(_) => pmtree::MerkleTree::new(depth, config.0)?,
        };

        Ok(PmTree {
            tree,
            cached_leaves_indices: vec![0; 1 << depth],
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
        self.tree.set_range(start, v.clone().into_iter())?;
        for i in start..v.len() {
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
            let node = self
                .tree
                .get_elem(Key::new(n, index >> (self.depth() - n)))
                .unwrap();
            Ok(node)
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
        let mut indices = indices.into_iter().collect::<Vec<_>>();
        indices.sort();

        match (leaves.len(), indices.len()) {
            (0, 0) => Err(ZerokitMerkleTreeError::InvalidLeaf),
            (1, 0) => self.set(start, leaves[0]),
            (0, 1) => self.delete(indices[0]),
            (_, 0) => self.set_range(start, leaves.into_iter()),
            (0, _) => self
                .remove_indices(&indices)
                .map_err(ZerokitMerkleTreeError::PmtreeErrorKind),
            (_, _) => self
                .remove_indices_and_set_leaves(start, leaves, &indices)
                .map_err(ZerokitMerkleTreeError::PmtreeErrorKind),
        }
    }

    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<(), ZerokitMerkleTreeError> {
        self.tree
            .update_next(leaf)
            .map_err(ZerokitMerkleTreeError::PmtreeErrorKind)
    }

    /// Delete a leaf in the merkle tree given its index
    ///
    /// Deleting a leaf is done by resetting it to its default value. Note that the next_index field
    /// will not be changed (== previously used index cannot be reused - this to avoid replay
    /// attacks or unexpected and very hard to tackle issues)
    fn delete(&mut self, index: usize) -> Result<(), ZerokitMerkleTreeError> {
        self.tree
            .delete(index)
            .map_err(ZerokitMerkleTreeError::PmtreeErrorKind)?;
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
        witness: &Self::Proof,
    ) -> Result<bool, ZerokitMerkleTreeError> {
        if self.tree.verify(leaf, &witness.proof) {
            Ok(true)
        } else {
            Err(ZerokitMerkleTreeError::InvalidWitness)
        }
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), ZerokitMerkleTreeError> {
        self.tree
            .db
            .put(METADATA_KEY, metadata.to_vec())
            .map_err(ZerokitMerkleTreeError::PmtreeErrorKind)?;
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>, ZerokitMerkleTreeError> {
        if !self.metadata.is_empty() {
            return Ok(self.metadata.clone());
        }
        // if empty, try searching the db
        let data = self.tree.db.get(METADATA_KEY)?;

        if data.is_none() {
            // send empty Metadata
            return Ok(Vec::new());
        }
        Ok(data.unwrap())
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
        let start = indices[0];
        let end = indices.last().unwrap() + 1;

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
    ) -> Result<(), PmtreeErrorKind> {
        let min_index = *indices.first().unwrap();
        let max_index = start + leaves.len();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmtree_config() {
        let json = r#"
        {
            "path": "pmtree-123456",
            "temporary": false,
            "cache_capacity": 150000,
            "flush_every_ms": 12000,
            "mode": "HighThroughput",
            "use_compression": false
        }"#;

        let _: PmtreeConfig = json.parse().expect("Failed to parse JSON config");

        let _ = PmtreeConfig::builder()
            .path(get_tmp_path())
            .temporary(false)
            .cache_capacity(150_000)
            .mode(Mode::HighThroughput)
            .use_compression(false)
            .build()
            .expect("Failed to build config");
    }
}
