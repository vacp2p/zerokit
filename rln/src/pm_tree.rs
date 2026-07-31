#![cfg(not(target_arch = "wasm32"))]

use std::{collections::HashMap, fmt::Debug, path::PathBuf, str::FromStr, thread, time::Duration};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bon::bon;
use pmtree::{
    DBKey, Database, Hasher as PmTreeHasher, MerkleTree, PmtreeError, PmtreeResult, MAX_DEPTH,
};
use serde_json::Value;
use sled::{Config, Db, Mode};
use tempfile::Builder;
use zerokit_utils::{
    hasher::ZerokitHasher,
    merkle_tree::{FromConfigError, ZerokitMerkleProof, ZerokitMerkleTree, ZerokitMerkleTreeError},
};

use crate::hashers::{Hasher, PoseidonHash};

/// The key used to store the metadata in database.
const METADATA_KEY: [u8; 8] = *b"metadata";

/// The sled database mode used by the [`PmTreeSledConfig`] backend.
pub type PmTreeMode = Mode;

impl PmTreeHasher for PoseidonHash {
    type Scalar = <PoseidonHash as ZerokitHasher>::Scalar;

    fn serialize(value: Self::Scalar) -> PmtreeResult<pmtree::Value> {
        let mut bytes = Vec::with_capacity(value.compressed_size());
        value
            .serialize_compressed(&mut bytes)
            .map_err(|err| PmtreeError::Hasher(format!("Cannot serialize Scalar: {err}")))?;
        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> PmtreeResult<Self::Scalar> {
        let value = Self::Scalar::deserialize_compressed(bytes)
            .map_err(|err| PmtreeError::Hasher(format!("Cannot deserialize Scalar: {err}")))?;
        Ok(value)
    }

    fn hash_pair(left: Self::Scalar, right: Self::Scalar) -> Self::Scalar {
        Hasher::<PoseidonHash>::hash_pair(left, right)
    }
}

/// A trait for the configuration of [`PmTree`] backends.
pub trait PmTreeBackendConfig: Clone + Default + FromStr {
    /// The tree depth this config expects; rechecked against the requested depth on reload.
    fn tree_depth(&self) -> Option<usize>;

    /// Returns `true` when no persisted tree exists, so a new one is initialized; `false`
    /// loads the existing tree and propagates load errors. In-memory backends return `true`.
    fn is_fresh(&self) -> bool;
}

/// A persistent Merkle tree over a [`pmtree::Database`] backend (sled by default).
/// Generic over the backend `D`: adding one is just `impl pmtree::Database` with a
/// `type Config:` [`PmTreeBackendConfig`], and all tree logic here is reused.
///
/// The backend's `put_batch` method must be atomic for crash-safety.
pub struct PmTree<D: Database, H: PmTreeHasher> {
    /// The underlying Merkle tree from the pmtree crate
    tree: MerkleTree<D, H>,
    /// The indices of leaves which are set into zero upto `next_index`.
    /// Set to 0 if the leaf is empty and set to 1 in otherwise.
    ///
    /// On reload, occupancy is rebuilt from stored values (sled keeps only values), so a leaf
    /// explicitly written with `default_leaf` reads as empty after a close/reopen. Affects only the
    /// raw `set`/`set_range`/`override_range`/`update_next` API; RLN leaves are rate commitments,
    /// never default.
    cached_leaves_indices: Vec<u8>,
    /// Metadata that an application may use to store additional information
    metadata: Vec<u8>,
}

/// A Merkle proof produced by [`PmTree`].
pub struct PmTreeProof<H: PmTreeHasher> {
    proof: pmtree::tree::MerkleProof<H>,
}

/// Errors that can occur while operating a [`PmTree`].
#[derive(Debug, thiserror::Error)]
pub enum PmTreeError {
    /// A Merkle tree validation error shared by all backends.
    #[error(transparent)]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    /// A genuine backend fault from the underlying database or hasher.
    #[error(transparent)]
    Backend(#[from] PmtreeError),
}

const DEFAULT_TEMPORARY: bool = true;
const DEFAULT_CACHE_CAPACITY: u64 = 1073741824; // 1 Gigabyte
const DEFAULT_FLUSH_EVERY_MS: u64 = 500; // 500 Milliseconds
const DEFAULT_MODE: PmTreeMode = PmTreeMode::HighThroughput;
const DEFAULT_USE_COMPRESSION: bool = false;

/// Configuration for the sled-backed [`PmTree`] database.
#[derive(Debug, Clone)]
pub struct PmTreeSledConfig {
    path: PathBuf,
    temporary: bool,
    cache_capacity: u64,
    flush_every_ms: u64,
    mode: PmTreeMode,
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
impl PmTreeSledConfig {
    /// Starts building a [`PmTreeSledConfig`]; call `build` to construct it.
    #[allow(clippy::new_ret_no_self)]
    #[builder(start_fn = new, finish_fn = build)]
    pub fn create(
        tree_depth: Option<usize>,
        #[builder(into)] path: Option<PathBuf>,
        #[builder(default = DEFAULT_TEMPORARY)] temporary: bool,
        #[builder(default = DEFAULT_CACHE_CAPACITY)] cache_capacity: u64,
        #[builder(default = DEFAULT_FLUSH_EVERY_MS)] flush_every_ms: u64,
        #[builder(default = DEFAULT_MODE)] mode: PmTreeMode,
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

impl From<&PmTreeSledConfig> for Config {
    fn from(config: &PmTreeSledConfig) -> Self {
        Config::new()
            .temporary(config.temporary)
            .path(config.path.clone())
            .cache_capacity(config.cache_capacity)
            .flush_every_ms(Some(config.flush_every_ms))
            .mode(config.mode)
            .use_compression(config.use_compression)
    }
}

impl FromStr for PmTreeSledConfig {
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
            Some("LowSpace") => PmTreeMode::LowSpace,
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

impl Default for PmTreeSledConfig {
    fn default() -> Self {
        PmTreeSledConfig::new()
            .build()
            .expect("Default PmTreeSledConfig must be valid")
    }
}

impl PmTreeBackendConfig for PmTreeSledConfig {
    fn tree_depth(&self) -> Option<usize> {
        self.tree_depth
    }

    fn is_fresh(&self) -> bool {
        // Fresh when the path does not exist yet or is an empty directory.
        !self.path.exists()
            || self
                .path
                .read_dir()
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
    }
}

impl<D, H> ZerokitMerkleTree for PmTree<D, H>
where
    D: Database,
    D::Config: PmTreeBackendConfig,
    H: ZerokitHasher + PmTreeHasher<Scalar = <H as ZerokitHasher>::Scalar>,
    <H as ZerokitHasher>::Scalar: Debug + Copy + PartialEq + Default + Send + Sync,
{
    type Proof = PmTreeProof<H>;
    type Hasher = H;
    type Config = D::Config;
    type Error = PmTreeError;

    fn default(depth: usize) -> Result<Self, Self::Error> {
        let default_config = Self::Config::default();
        Self::new(depth, Self::Hasher::default_leaf(), default_config)
    }

    /// Creates a new tree, loading the existing one when the config is not fresh.
    fn new(
        depth: usize,
        _default_leaf: <H as ZerokitHasher>::Scalar,
        config: Self::Config,
    ) -> Result<Self, Self::Error> {
        if depth >= usize::BITS as usize || depth > MAX_DEPTH {
            return Err(ZerokitMerkleTreeError::DepthTooLarge.into());
        }
        if let Some(config_depth) = config.tree_depth() {
            if config_depth != depth {
                return Err(ZerokitMerkleTreeError::DepthMismatch.into());
            }
        }
        let tree = if config.is_fresh() {
            MerkleTree::new(depth, config)?
        } else {
            let tree = MerkleTree::load(config)?;
            if tree.depth() != depth {
                return Err(ZerokitMerkleTreeError::DepthMismatch.into());
            }
            tree
        };

        let capacity = 1usize
            .checked_shl(depth as u32)
            .ok_or(ZerokitMerkleTreeError::DepthTooLarge)?;

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

    /// Returns the depth of the tree
    fn depth(&self) -> usize {
        self.tree.depth()
    }

    /// Returns the capacity of the tree, i.e. the maximum number of accumulatable leaves
    fn capacity(&self) -> usize {
        self.tree.capacity()
    }

    /// Returns the total number of leaves set
    fn leaves_set(&self) -> usize {
        self.tree.leaves_set()
    }

    /// Returns the root of the tree
    fn root(&self) -> <H as ZerokitHasher>::Scalar {
        self.tree.root()
    }

    /// Returns the root of the subtree at `level` (`0` = root, `depth` = leaf) on the path to
    /// leaf `index`.
    fn get_subtree_root(
        &self,
        level: usize,
        index: usize,
    ) -> Result<<H as ZerokitHasher>::Scalar, Self::Error> {
        if level > self.depth() {
            return Err(ZerokitMerkleTreeError::LevelOutOfBounds.into());
        }
        if index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds.into());
        }
        self.tree.subtree_root(level, index).map_err(Into::into)
    }

    /// Sets a leaf at the specified tree index
    fn set(&mut self, index: usize, leaf: <H as ZerokitHasher>::Scalar) -> Result<(), Self::Error> {
        if index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds.into());
        }
        self.tree.set(index, leaf)?;
        self.cached_leaves_indices[index] = 1;
        Ok(())
    }

    /// Sets multiple leaves from the specified tree index
    fn set_range<I: IntoIterator<Item = <H as ZerokitHasher>::Scalar>>(
        &mut self,
        start: usize,
        values: I,
    ) -> Result<(), Self::Error> {
        let v = values.into_iter().collect::<Vec<_>>();
        let end = start
            .checked_add(v.len())
            .ok_or(ZerokitMerkleTreeError::RangeTooLarge)?;
        if end > self.capacity() {
            return Err(ZerokitMerkleTreeError::RangeTooLarge.into());
        }
        self.tree.set_range(start, &v)?;
        for i in start..start + v.len() {
            self.cached_leaves_indices[i] = 1
        }
        Ok(())
    }

    /// Get a leaf from the specified tree index
    fn get(&self, index: usize) -> Result<<H as ZerokitHasher>::Scalar, Self::Error> {
        if index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds.into());
        }
        self.tree.get(index).map_err(Into::into)
    }

    /// Returns the indices of the leaves that are empty
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

    /// Overrides a range atomically, reusing the shared [`Self::validate_override_range`].
    ///
    /// The resets and contiguous writes commit in one `pmtree` `batch_set`, so a persistent tree
    /// stays crash-safe.
    fn override_range<
        I: IntoIterator<Item = <H as ZerokitHasher>::Scalar>,
        J: IntoIterator<Item = usize>,
    >(
        &mut self,
        start: usize,
        leaves: I,
        indices: J,
    ) -> Result<(), Self::Error> {
        let leaves = leaves.into_iter().collect::<Vec<_>>();
        let to_remove = indices.into_iter().collect::<Vec<_>>();

        let deletes = self.validate_override_range(start, leaves.len(), &to_remove)?;

        // Build scattered (index, value) pairs (non-overlapping deletes as the default leaf, then
        // the contiguous writes) and commit them in ONE atomic batch.
        let default_leaf = H::default_leaf();
        let mut pairs = Vec::with_capacity(deletes.len() + leaves.len());
        for &index in &deletes {
            pairs.push((index, default_leaf));
        }
        for (offset, &leaf) in leaves.iter().enumerate() {
            pairs.push((start + offset, leaf));
        }
        self.tree.batch_set(&pairs)?;

        // Mirror the writes in the empty-leaves cache: deletes -> 0, writes -> 1.
        for &index in &deletes {
            self.cached_leaves_indices[index] = 0;
        }
        for offset in 0..leaves.len() {
            self.cached_leaves_indices[start + offset] = 1;
        }
        Ok(())
    }

    /// Sets a leaf at the next available index
    fn update_next(&mut self, leaf: <H as ZerokitHasher>::Scalar) -> Result<(), Self::Error> {
        if self.leaves_set() >= self.capacity() {
            return Err(ZerokitMerkleTreeError::RangeTooLarge.into());
        }
        let index = self.tree.leaves_set();
        self.tree.update_next(leaf)?;
        self.cached_leaves_indices[index] = 1;
        Ok(())
    }

    /// Deletes a leaf at a certain index by setting it to its default value (`next_index` is not
    /// updated)
    fn delete(&mut self, index: usize) -> Result<(), Self::Error> {
        if index >= self.leaves_set() {
            return Err(ZerokitMerkleTreeError::DeleteUnsetLeaf.into());
        }
        self.tree.delete(index)?;
        self.cached_leaves_indices[index] = 0;
        Ok(())
    }

    /// Computes a merkle proof the leaf at the specified index
    fn proof(&self, index: usize) -> Result<Self::Proof, Self::Error> {
        if index >= self.capacity() {
            return Err(ZerokitMerkleTreeError::LeafIndexOutOfBounds.into());
        }
        let proof = self.tree.proof(index)?;
        Ok(PmTreeProof { proof })
    }

    /// Verifies a Merkle proof with respect to the input leaf and the tree root
    fn verify(
        &self,
        leaf: &<H as ZerokitHasher>::Scalar,
        merkle_proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        if self.tree.verify(leaf, &merkle_proof.proof) {
            Ok(true)
        } else {
            Err(ZerokitMerkleTreeError::InvalidMerkleProof.into())
        }
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), Self::Error> {
        self.tree.db.put(METADATA_KEY, metadata.to_vec())?;
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>, Self::Error> {
        if !self.metadata.is_empty() {
            return Ok(self.metadata.clone());
        }
        // if empty, try searching the db
        let data = self.tree.db.get(METADATA_KEY)?;

        // Return empty metadata if not found, otherwise return the data
        Ok(data.unwrap_or_default())
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        self.tree.db.close().map_err(Into::into)
    }
}

impl<H> ZerokitMerkleProof for PmTreeProof<H>
where
    H: ZerokitHasher + PmTreeHasher<Scalar = <H as ZerokitHasher>::Scalar>,
    <H as ZerokitHasher>::Scalar: Debug + Copy + PartialEq + Default + Send + Sync,
{
    type Index = u8;
    type Hasher = H;

    fn length(&self) -> usize {
        self.proof.length()
    }

    fn leaf_index(&self) -> usize {
        self.proof.leaf_index()
    }

    fn get_path_elements(&self) -> Vec<<H as ZerokitHasher>::Scalar> {
        self.proof.get_path_elements()
    }

    fn get_path_index(&self) -> Vec<Self::Index> {
        self.proof.get_path_index()
    }

    fn compute_root_from(
        &self,
        leaf: &<H as ZerokitHasher>::Scalar,
    ) -> <H as ZerokitHasher>::Scalar {
        self.proof.compute_root_from(leaf)
    }
}

/// A wrapper around sled::Db to implement the Database trait for pmtree.
pub struct SledDB(Db);

impl SledDB {
    fn new_with_tries(config: Config, tries: u32) -> PmtreeResult<Self> {
        // If we've tried more than 10 times, we give up and return an error.
        if tries >= 10 {
            return Err(PmtreeError::Database(format!(
                "Cannot create database: exceeded maximum retry attempts. {config:#?}"
            )));
        }
        match config.open() {
            Ok(db) => Ok(SledDB(db)),
            Err(err) if err.to_string().contains("WouldBlock") => {
                // try till the fd is freed
                // sleep for 10^tries milliseconds, then recursively try again
                thread::sleep(Duration::from_millis(10u64.pow(tries)));
                Self::new_with_tries(config, tries + 1)
            }
            Err(err) => {
                // On any other error, we return immediately.
                Err(PmtreeError::Database(format!(
                    "Cannot create database: {err} {config:#?}"
                )))
            }
        }
    }
}

impl Database for SledDB {
    type Config = PmTreeSledConfig;

    fn new(config: Self::Config) -> PmtreeResult<Self> {
        let db = Self::new_with_tries(Config::from(&config), 0)?;
        Ok(db)
    }

    fn load(config: Self::Config) -> PmtreeResult<Self> {
        let sled_config = Config::from(&config);
        let path = sled_config.path.clone();
        let SledDB(db) = Self::new_with_tries(sled_config, 0)?;

        if !db.was_recovered() {
            return Err(PmtreeError::Database(format!(
                "Database was not recovered: {}",
                path.display()
            )));
        }

        Ok(SledDB(db))
    }

    fn close(&mut self) -> PmtreeResult<()> {
        self.0
            .flush()
            .map_err(|err| PmtreeError::Database(format!("Cannot flush database: {err}")))?;
        Ok(())
    }

    fn get(&self, key: DBKey) -> PmtreeResult<Option<pmtree::Value>> {
        match self.0.get(key) {
            Ok(value) => Ok(value.map(|val| val.to_vec())),
            Err(err) => Err(PmtreeError::Database(format!(
                "Cannot read from database: {err}"
            ))),
        }
    }

    fn put(&mut self, key: DBKey, value: pmtree::Value) -> PmtreeResult<()> {
        match self.0.insert(key, value) {
            Ok(_) => Ok(()),
            Err(err) => Err(PmtreeError::Database(format!(
                "Cannot write to database: {err}"
            ))),
        }
    }

    fn put_batch(&mut self, subtree: HashMap<DBKey, pmtree::Value>) -> PmtreeResult<()> {
        let mut batch = sled::Batch::default();

        for (key, value) in subtree {
            batch.insert(&key, value);
        }

        self.0
            .apply_batch(batch)
            .map_err(|err| PmtreeError::Database(format!("Cannot apply database batch: {err}")))?;
        Ok(())
    }
}
