use crate::circuit::Fr;
use crate::hashers::{poseidon_hash, PoseidonHash};
use crate::utils::{bytes_le_to_fr, fr_to_bytes_le};
use color_eyre::{Report, Result};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt::Debug;
use std::path::PathBuf;
use std::str::FromStr;
use utils::pmtree::{Database, Hasher};
use utils::*;

const METADATA_KEY: [u8; 8] = *b"metadata";

pub struct PmTree {
    tree: pmtree::MerkleTree<SledDB, PoseidonHash>,
    // metadata that an application may use to store additional information
    metadata: Vec<u8>,
}

pub struct PmTreeProof {
    proof: pmtree::tree::MerkleProof<PoseidonHash>,
}

pub type FrOf<H> = <H as Hasher>::Fr;

// The pmtree Hasher trait used by pmtree Merkle tree
impl pmtree::Hasher for PoseidonHash {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Fr::from(0)
    }

    fn serialize(value: Self::Fr) -> pmtree::Value {
        fr_to_bytes_le(&value)
    }

    fn deserialize(value: pmtree::Value) -> Self::Fr {
        let (fr, _) = bytes_le_to_fr(&value);
        fr
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}

fn get_tmp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("pmtree-{}", rand::random::<u64>()))
}

fn get_tmp() -> bool {
    true
}

pub struct PmtreeConfig(pm_tree::Config);

impl FromStr for PmtreeConfig {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self> {
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
            return Err(Report::msg(format!(
                "Path {:?} already exists, cannot use temporary",
                path.unwrap()
            )));
        }

        let config = pm_tree::Config::new()
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
            pm_tree::Config::new()
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

    fn default(depth: usize) -> Result<Self> {
        let default_config = PmtreeConfig::default();
        PmTree::new(depth, Self::Hasher::default_leaf(), default_config)
    }

    fn new(depth: usize, _default_leaf: FrOf<Self::Hasher>, config: Self::Config) -> Result<Self> {
        let tree_loaded = pmtree::MerkleTree::load(config.clone().0);
        let tree = match tree_loaded {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{}", e);
                pmtree::MerkleTree::new(depth, config.0)?
            },
        };

        Ok(PmTree {
            tree,
            metadata: Vec::new(),
        })
    }

    fn close_db_connection(&mut self) -> Result<()> {
        self.tree.db.close().map_err(|e| Report::msg(e.to_string()))
    }

    fn depth(&self) -> usize {
        self.tree.depth()
    }

    fn capacity(&self) -> usize {
        self.tree.capacity()
    }

    fn leaves_set(&mut self) -> usize {
        self.tree.leaves_set()
    }

    fn root(&self) -> FrOf<Self::Hasher> {
        self.tree.root()
    }

    fn set(&mut self, index: usize, leaf: FrOf<Self::Hasher>) -> Result<()> {
        self.tree
            .set(index, leaf)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn get(&self, index: usize) -> Result<FrOf<Self::Hasher>> {
        self.tree.get(index).map_err(|e| Report::msg(e.to_string()))
    }

    fn set_range<I: IntoIterator<Item = FrOf<Self::Hasher>>>(
        &mut self,
        start: usize,
        values: I,
    ) -> Result<()> {
        self.tree
            .set_range(start, values)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn override_range<I: IntoIterator<Item = FrOf<Self::Hasher>>, J: IntoIterator<Item = usize>>(
        &mut self,
        start: usize,
        leaves: I,
        indices: J,
    ) -> Result<()> {
        let leaves = leaves.into_iter().collect::<Vec<_>>();
        let indices = indices.into_iter().collect::<HashSet<_>>();
        let end = start + leaves.len();

        if leaves.len() + start - indices.len() > self.capacity() {
            return Err(Report::msg("index out of bounds"));
        }

        // extend the range to include indices to be removed
        let min_index = indices.iter().min().unwrap_or(&start);
        let max_index = indices.iter().max().unwrap_or(&end);

        let mut new_leaves = Vec::new();

        // insert leaves into new_leaves
        for i in *min_index..*max_index {
            if indices.contains(&i) {
                // insert 0
                new_leaves.push(Self::Hasher::default_leaf());
            } else {
                // insert leaf
                new_leaves.push(leaves[i - start]);
            }
        }

        self.tree
            .set_range(start, new_leaves)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn update_next(&mut self, leaf: FrOf<Self::Hasher>) -> Result<()> {
        self.tree
            .update_next(leaf)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn delete(&mut self, index: usize) -> Result<()> {
        self.tree
            .delete(index)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn proof(&self, index: usize) -> Result<Self::Proof> {
        let proof = self.tree.proof(index)?;
        Ok(PmTreeProof { proof })
    }

    fn verify(&self, leaf: &FrOf<Self::Hasher>, witness: &Self::Proof) -> Result<bool> {
        if self.tree.verify(leaf, &witness.proof) {
            Ok(true)
        } else {
            Err(Report::msg("verify failed"))
        }
    }

    fn compute_root(&mut self) -> Result<FrOf<Self::Hasher>> {
        Ok(self.tree.root())
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<()> {
        self.tree.db.put(METADATA_KEY, metadata.to_vec())?;
        self.metadata = metadata.to_vec();
        Ok(())
    }

    fn metadata(&self) -> Result<Vec<u8>> {
        if !self.metadata.is_empty() {
            return Ok(self.metadata.clone());
        }
        // if empty, try searching the db
        let data = self.tree.db.get(METADATA_KEY)?;

        if data.is_none() {
            return Err(Report::msg("metadata does not exist"));
        }
        Ok(data.unwrap())
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
