// This module is the main public API for RLN module

use std::{marker::PhantomData, sync::Arc};

use bon::bon;
use zerokit_utils::merkle_tree::{Hasher, ZerokitMerkleTree, ZerokitMerkleTreeError};

#[cfg(not(target_arch = "wasm32"))]
use crate::circuit::{default_graph_single, default_zkey_single};
use crate::{
    circuit::{ArkGroth16Backend, Fr, Graph, Proof, Zkey},
    error::VerifyProofError,
    protocol::{RLNPartialZkProof, RLNProofValues, RLNZkProof},
};

/// Type-state marker for an RLN instance that owns a Merkle tree.
#[derive(Debug, Clone)]
pub struct Stateful<T> {
    pub tree: T,
}

impl<T> Stateful<T> {
    pub fn new(tree: T) -> Self {
        Self { tree }
    }

    pub fn tree(&self) -> &T {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut T {
        &mut self.tree
    }

    pub fn into_tree(self) -> T {
        self.tree
    }
}

/// Type-state marker for an RLN instance without tree state.
#[derive(Debug, Clone)]
pub struct Stateless;

pub struct RLN<State, ZkProof> {
    pub(crate) zkp: ZkProof,
    pub(crate) state: State,
}

impl<ZkProof> RLN<Stateless, ZkProof> {
    pub fn new(zkp: ZkProof) -> Self {
        Self {
            zkp,
            state: Stateless,
        }
    }
}

impl<T, ZkProof> RLN<Stateful<T>, ZkProof> {
    pub fn new(tree: T, zkp: ZkProof) -> Self {
        Self {
            zkp,
            state: Stateful::new(tree),
        }
    }
}

impl<T, ZkProof> RLN<Stateful<T>, ZkProof> {
    pub fn tree(&self) -> &T {
        self.state.tree()
    }

    pub fn tree_mut(&mut self) -> &mut T {
        self.state.tree_mut()
    }

    pub fn into_tree(self) -> T {
        self.state.into_tree()
    }
}

impl<T, ZkProof> RLN<Stateful<T>, ZkProof>
where
    T: ZerokitMerkleTree,
    T::Hasher: Hasher<Fr = Fr>,
{
    pub fn tree_depth(&self) -> usize {
        self.state.tree.depth()
    }

    pub fn get_root(&self) -> Fr {
        self.state.tree.root()
    }

    pub fn set_leaf(&mut self, index: usize, leaf: Fr) -> Result<(), ZerokitMerkleTreeError> {
        self.state.tree.set(index, leaf)
    }

    pub fn get_leaf(&self, index: usize) -> Result<Fr, ZerokitMerkleTreeError> {
        self.state.tree.get(index)
    }

    pub fn set_leaves_from(
        &mut self,
        index: usize,
        leaves: Vec<Fr>,
    ) -> Result<(), ZerokitMerkleTreeError> {
        self.state.tree.set_range(index, leaves.into_iter())
    }

    pub fn init_tree_with_leaves(&mut self, leaves: Vec<Fr>) -> Result<(), ZerokitMerkleTreeError> {
        let depth = self.state.tree.depth();
        self.state.tree = T::default(depth)?;
        self.set_leaves_from(0, leaves)
    }

    pub fn atomic_operation(
        &mut self,
        index: usize,
        leaves: Vec<Fr>,
        indices: Vec<usize>,
    ) -> Result<(), ZerokitMerkleTreeError> {
        self.state
            .tree
            .override_range(index, leaves.into_iter(), indices.into_iter())
    }

    pub fn leaves_set(&self) -> usize {
        self.state.tree.leaves_set()
    }

    pub fn set_next_leaf(&mut self, leaf: Fr) -> Result<(), ZerokitMerkleTreeError> {
        self.state.tree.update_next(leaf)
    }

    pub fn delete_leaf(&mut self, index: usize) -> Result<(), ZerokitMerkleTreeError> {
        self.state.tree.delete(index)
    }

    pub fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), ZerokitMerkleTreeError> {
        self.state.tree.set_metadata(metadata)
    }

    pub fn get_metadata(&self) -> Result<Vec<u8>, ZerokitMerkleTreeError> {
        self.state.tree.metadata()
    }

    pub fn get_subtree_root(
        &self,
        level: usize,
        index: usize,
    ) -> Result<Fr, ZerokitMerkleTreeError> {
        self.state.tree.get_subtree_root(level, index)
    }

    pub fn get_empty_leaves_indices(&self) -> Vec<usize> {
        self.state.tree.get_empty_leaves_indices()
    }

    pub fn flush(&mut self) -> Result<(), ZerokitMerkleTreeError> {
        self.state.tree.close_db_connection()
    }

    pub fn get_merkle_proof(&self, index: usize) -> Result<T::Proof, ZerokitMerkleTreeError> {
        self.state.tree.proof(index)
    }
}

impl<Tree, ZkProof: RLNZkProof> RLN<Tree, ZkProof> {
    pub fn generate_proof(
        &self,
        witness: &ZkProof::Witness,
    ) -> Result<(ZkProof::Proof, ZkProof::Values), ZkProof::GenerateProofError> {
        self.zkp.generate_proof(witness)
    }

    pub fn verify(
        &self,
        proof: &ZkProof::Proof,
        values: &ZkProof::Values,
    ) -> Result<bool, ZkProof::VerifyProofError> {
        self.zkp.verify(proof, values)
    }
}

impl<Tree, ZkProof: RLNPartialZkProof> RLN<Tree, ZkProof> {
    pub fn generate_partial_proof(
        &self,
        partial_witness: &ZkProof::PartialWitness,
    ) -> Result<ZkProof::PartialProof, ZkProof::GeneratePartialProofError> {
        self.zkp.generate_partial_proof(partial_witness)
    }

    pub fn finish_proof(
        &self,
        partial_proof: &ZkProof::PartialProof,
        witness: &ZkProof::Witness,
    ) -> Result<(ZkProof::Proof, ZkProof::Values), ZkProof::FinishProofError> {
        self.zkp.finish_proof(partial_proof, witness)
    }
}

impl<Tree, ZkProof> RLN<Tree, ZkProof>
where
    ZkProof:
        RLNZkProof<Values = RLNProofValues, Proof = Proof, VerifyProofError = VerifyProofError>,
{
    pub fn verify_with_signal(
        &self,
        proof: &Proof,
        values: &RLNProofValues,
        x: &Fr,
    ) -> Result<bool, VerifyProofError> {
        if x != &values.x() {
            return Err(VerifyProofError::InvalidSignal);
        }
        if !self.zkp.verify(proof, values)? {
            return Err(VerifyProofError::InvalidProof);
        }
        Ok(true)
    }

    pub fn verify_with_roots(
        &self,
        proof: &Proof,
        values: &RLNProofValues,
        x: &Fr,
        roots: &[Fr],
    ) -> Result<bool, VerifyProofError> {
        if !roots.is_empty() && !roots.contains(&values.root()) {
            return Err(VerifyProofError::InvalidRoot);
        }
        self.verify_with_signal(proof, values, x)
    }
}

pub struct RLNBuilder<ZKP>(PhantomData<ZKP>);

#[bon]
impl RLNBuilder<ArkGroth16Backend> {
    #[builder(finish_fn = build)]
    pub fn stateless(
        #[cfg_attr(
            not(target_arch = "wasm32"),
            builder(default = default_graph_single().clone(), into)
        )]
        #[cfg_attr(target_arch = "wasm32", builder(into))]
        graph: Arc<Graph>,
        #[cfg_attr(
            not(target_arch = "wasm32"),
            builder(default = default_zkey_single().clone(), into)
        )]
        #[cfg_attr(target_arch = "wasm32", builder(into))]
        zkey: Arc<Zkey>,
    ) -> RLN<Stateless, ArkGroth16Backend> {
        RLN::<Stateless, ArkGroth16Backend>::new(ArkGroth16Backend::new(zkey, graph))
    }

    #[builder(finish_fn = build)]
    pub fn stateful<Tree>(
        tree: Tree,
        #[cfg_attr(
            not(target_arch = "wasm32"),
            builder(default = default_graph_single().clone(), into)
        )]
        #[cfg_attr(target_arch = "wasm32", builder(into))]
        graph: Arc<Graph>,
        #[cfg_attr(
            not(target_arch = "wasm32"),
            builder(default = default_zkey_single().clone(), into)
        )]
        #[cfg_attr(target_arch = "wasm32", builder(into))]
        zkey: Arc<Zkey>,
    ) -> RLN<Stateful<Tree>, ArkGroth16Backend> {
        RLN::<Stateful<Tree>, ArkGroth16Backend>::new(tree, ArkGroth16Backend::new(zkey, graph))
    }
}
