use crate::circuit::Fr;
use crate::pm_tree_adapter::pm_tree::Config;
use crate::poseidon_hash::{poseidon_hash, PoseidonHash};
use crate::utils::{bytes_le_to_fr, fr_to_bytes_le};
use color_eyre::{Report, Result};
use utils::pm_tree;
use utils::*;

pub struct PmTree {
    tree: pmtree::MerkleTree<SledDB, PoseidonHash>,
}

pub struct PmTreeProof {
    proof: pmtree::tree::MerkleProof<PoseidonHash>,
}

pub type FrOfHasher = <PoseidonHash as Hasher>::Fr;

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

impl ZerokitMerkleTree for PmTree {
    type Proof = PmTreeProof;
    type Hasher = PoseidonHash;

    fn default(depth: usize) -> Result<Self> {
        PmTree::new(depth, Self::Hasher::default_leaf())
    }

    fn new(depth: usize, _default_leaf: FrOfHasher) -> Result<Self> {
        let config = Config::new().temporary(true).create_new(true);
        let tree = pm_tree::pmtree::MerkleTree::new(depth, config)?;
        Ok(PmTree { tree })
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

    fn root(&self) -> FrOfHasher {
        self.tree.root()
    }

    fn set(&mut self, index: usize, leaf: FrOfHasher) -> Result<()> {
        self.tree
            .set(index, leaf)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn set_range<I: IntoIterator<Item = FrOfHasher>>(
        &mut self,
        start: usize,
        values: I,
    ) -> Result<()> {
        self.tree
            .set_range(start, values)
            .map_err(|e| Report::msg(e.to_string()))
    }

    fn update_next(&mut self, leaf: FrOfHasher) -> Result<()> {
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

    fn verify(&self, leaf: &FrOfHasher, witness: &Self::Proof) -> Result<bool> {
        if self.tree.verify(leaf, &witness.proof) {
            Ok(true)
        } else {
            Err(Report::msg("verify failed"))
        }
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

    fn get_path_elements(&self) -> Vec<FrOfHasher> {
        self.proof.get_path_elements()
    }

    fn get_path_index(&self) -> Vec<Self::Index> {
        self.proof.get_path_index()
    }
    fn compute_root_from(&self, leaf: &FrOfHasher) -> FrOfHasher {
        self.proof.compute_root_from(leaf)
    }
}
