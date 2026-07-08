// This module is the main public API for RLN module.

use std::{marker::PhantomData, sync::Arc};

use bon::bon;
use zerokit_utils::{hasher::ZerokitHasher, merkle_tree::ZerokitMerkleTree};

#[cfg(not(target_arch = "wasm32"))]
use crate::circuit::{default_graph_single, default_zkey_single};
use crate::{
    circuit::{ArkGroth16Backend, Fr, Graph, Proof, Zkey},
    error::VerifyProofError,
    hashers::PoseidonHash,
    protocol::{RLNPartialZkProof, RLNProofValues, RLNZkProof},
};

/// Type-state marker for an [`RLN`] instance that owns a Merkle tree.
#[derive(Debug, Clone)]
pub struct Stateful<T> {
    /// The Merkle tree owned by the RLN instance.
    pub tree: T,
}

impl<T> Stateful<T> {
    /// Creates a new [`Stateful`] marker wrapping the given `tree`.
    pub fn new(tree: T) -> Self {
        Self { tree }
    }

    /// Returns a shared reference to the owned Merkle tree.
    pub fn tree(&self) -> &T {
        &self.tree
    }

    /// Returns a mutable reference to the owned Merkle tree.
    pub fn tree_mut(&mut self) -> &mut T {
        &mut self.tree
    }

    /// Consumes the marker and returns the owned Merkle tree.
    pub fn into_tree(self) -> T {
        self.tree
    }
}

/// Type-state marker for an [`RLN`] instance without a Merkle tree.
#[derive(Debug, Clone)]
pub struct Stateless;

/// The RLN object.
///
/// It implements the methods required to update the internal Merkle tree and to generate and
/// verify RLN zkSNARK proofs. The `State` type parameter is either [`Stateful`] (owns a Merkle
/// tree) or [`Stateless`] (no tree); `ZkProof` is the zkSNARK backend.
pub struct RLN<State, ZkProof> {
    pub(crate) state: State,
    pub(crate) zkp: ZkProof,
}

impl<ZkProof> RLN<Stateless, ZkProof> {
    /// Creates a new stateless RLN instance from a zkSNARK backend `zkp`.
    pub fn new(zkp: ZkProof) -> Self {
        Self {
            state: Stateless,
            zkp,
        }
    }
}

impl<T, ZkProof> RLN<Stateful<T>, ZkProof>
where
    ZkProof: RLNZkProof,
    T: ZerokitMerkleTree<Hasher = ZkProof::Hasher>,
{
    /// Creates a new stateful RLN instance from a Merkle `tree` and a zkSNARK backend `zkp`.
    pub fn new(tree: T, zkp: ZkProof) -> Self {
        Self {
            state: Stateful::new(tree),
            zkp,
        }
    }
}

impl<T, ZkProof> RLN<Stateful<T>, ZkProof> {
    /// Returns a shared reference to the internal Merkle tree.
    pub fn tree(&self) -> &T {
        self.state.tree()
    }

    /// Returns a mutable reference to the internal Merkle tree.
    pub fn tree_mut(&mut self) -> &mut T {
        self.state.tree_mut()
    }

    /// Consumes the RLN instance and returns the internal Merkle tree.
    pub fn into_tree(self) -> T {
        self.state.into_tree()
    }
}

impl<T, ZkProof> RLN<Stateful<T>, ZkProof>
where
    T: ZerokitMerkleTree,
    T::Hasher: ZerokitHasher<Scalar = Fr>,
{
    /// Returns the depth of the internal Merkle tree.
    pub fn tree_depth(&self) -> usize {
        self.state.tree.depth()
    }

    /// Returns the number of leaves that have been set in the internal Merkle tree.
    pub fn leaves_set(&self) -> usize {
        self.state.tree.leaves_set()
    }

    /// Returns the root of the internal Merkle tree.
    pub fn get_root(&self) -> Fr {
        self.state.tree.root()
    }

    /// Returns the root of the subtree at the given `level` on the path to leaf `index`
    /// (`level` `0` is the tree root, `level` equal to the tree depth is the leaf).
    pub fn get_subtree_root(&self, level: usize, index: usize) -> Result<Fr, T::Error> {
        self.state.tree.get_subtree_root(level, index)
    }

    /// Sets the `leaf` value at position `index` in the internal Merkle tree.
    pub fn set_leaf(&mut self, index: usize, leaf: Fr) -> Result<(), T::Error> {
        self.state.tree.set(index, leaf)
    }

    /// Sets multiple `leaves` starting from position `index` in the internal Merkle tree.
    ///
    /// If `n` leaves are passed, they are set at positions `index`, `index + 1`, ...,
    /// `index + n - 1`. The internal `next_index` (the next never-set index) is updated to
    /// `max(next_index, index + n)`.
    pub fn set_leaves_from(&mut self, index: usize, leaves: Vec<Fr>) -> Result<(), T::Error> {
        self.state.tree.set_range(index, leaves.into_iter())
    }

    /// Resets the tree to its default state and sets `leaves` starting from index `0`.
    ///
    /// In contrast to [`Self::set_leaves_from`], this resets the internal `next_index` to `0`
    /// before setting the input leaves. The tree keeps its current depth.
    pub fn init_tree_with_leaves(&mut self, leaves: Vec<Fr>) -> Result<(), T::Error> {
        let depth = self.state.tree.depth();
        self.state.tree = T::default(depth)?;
        self.set_leaves_from(0, leaves)
    }

    /// Returns the leaf value at position `index` in the internal Merkle tree.
    pub fn get_leaf(&self, index: usize) -> Result<Fr, T::Error> {
        self.state.tree.get(index)
    }

    /// Returns the indices of the leaves set to the default value, up to the last set leaf.
    pub fn get_empty_leaves_indices(&self) -> Vec<usize> {
        self.state.tree.get_empty_leaves_indices()
    }

    /// Atomically sets `leaves` starting from position `index` and removes `indices` from the tree.
    ///
    /// The `leaves` are written at positions `index`, `index + 1`, ..., and each entry of `indices`
    /// is reset to the default value (writes win on overlap). The internal `next_index` is updated
    /// as in [`Self::set_leaves_from`].
    pub fn atomic_operation(
        &mut self,
        index: usize,
        leaves: Vec<Fr>,
        indices: Vec<usize>,
    ) -> Result<(), T::Error> {
        self.state.tree.override_range(index, leaves, indices)
    }

    /// Sets a `leaf` at the next available never-set index, incrementing `next_index` by one.
    pub fn set_next_leaf(&mut self, leaf: Fr) -> Result<(), T::Error> {
        self.state.tree.update_next(leaf)
    }

    /// Resets the leaf at position `index` to the default value, leaving `next_index` unchanged.
    pub fn delete_leaf(&mut self, index: usize) -> Result<(), T::Error> {
        self.state.tree.delete(index)
    }

    /// Returns the Merkle proof for the leaf at position `index`.
    pub fn get_merkle_proof(&self, index: usize) -> Result<T::Proof, T::Error> {
        self.state.tree.proof(index)
    }

    /// Stores application-defined `metadata` in the tree; the metadata is not used by RLN itself.
    pub fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), T::Error> {
        self.state.tree.set_metadata(metadata)
    }

    /// Returns the application-defined metadata stored in the tree.
    pub fn get_metadata(&self) -> Result<Vec<u8>, T::Error> {
        self.state.tree.metadata()
    }

    /// Closes the tree, flushing pending writes for persistent backends.
    ///
    /// Persistent backends also flush on drop; for in-memory backends this is a no-op.
    pub fn close(&mut self) -> Result<(), T::Error> {
        self.state.tree.close()
    }
}

impl<State, ZkProof> RLN<State, ZkProof>
where
    ZkProof: RLNZkProof,
{
    /// Generates a proof and its proof values from a `witness`.
    pub fn generate_proof(
        &self,
        witness: &ZkProof::Witness,
    ) -> Result<(ZkProof::Proof, ZkProof::Values), ZkProof::GenerateProofError> {
        self.zkp.generate_proof(witness)
    }

    /// Verifies a `proof` against its proof `values` (zkSNARK verification only).
    pub fn verify(
        &self,
        proof: &ZkProof::Proof,
        values: &ZkProof::Values,
    ) -> Result<bool, ZkProof::VerifyProofError> {
        self.zkp.verify(proof, values)
    }
}

impl<State, ZkProof> RLN<State, ZkProof>
where
    ZkProof: RLNPartialZkProof,
{
    /// Generates a partial proof from `partial_witness` inputs.
    ///
    /// This is the first step of two-step proof generation; complete it with
    /// [`Self::finish_proof`].
    pub fn generate_partial_proof(
        &self,
        partial_witness: &ZkProof::PartialWitness,
    ) -> Result<ZkProof::PartialProof, ZkProof::GeneratePartialProofError> {
        self.zkp.generate_partial_proof(partial_witness)
    }

    /// Completes proof generation from a `partial_proof` and the full `witness`.
    ///
    /// This is the second step of two-step proof generation, following
    /// [`Self::generate_partial_proof`].
    pub fn finish_proof(
        &self,
        partial_proof: &ZkProof::PartialProof,
        witness: &ZkProof::Witness,
    ) -> Result<(ZkProof::Proof, ZkProof::Values), ZkProof::FinishProofError> {
        self.zkp.finish_proof(partial_proof, witness)
    }
}

impl<State, ZkProof> RLN<State, ZkProof>
where
    ZkProof:
        RLNZkProof<Values = RLNProofValues, Proof = Proof, VerifyProofError = VerifyProofError>,
{
    /// Verifies a `proof` against its proof `values` and checks that the signal `x` matches the
    /// value bound in the proof.
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

    /// Verifies a `proof` against its proof `values`, checks the signal `x`, and checks that the
    /// proof root is among `roots`.
    ///
    /// If `roots` is empty, the root check is skipped. The signal check is the same as in
    /// [`Self::verify_with_signal`].
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

/// Builder for [`RLN`] instances backed by [`ArkGroth16Backend`] with [`PoseidonHash`].
pub struct RLNBuilder<ZKP>(PhantomData<ZKP>);

#[bon]
impl RLNBuilder<ArkGroth16Backend<PoseidonHash>> {
    /// Builds a [`Stateless`] RLN instance from the circuit `graph` and `zkey` resources.
    ///
    /// On native targets both resources default to the single message-id circuit; on `wasm32`
    /// they must be supplied.
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
    ) -> RLN<Stateless, ArkGroth16Backend<PoseidonHash>> {
        RLN::<Stateless, _>::new(ArkGroth16Backend::new(zkey, graph))
    }

    /// Builds a [`Stateful`] RLN instance from a Merkle `tree` and the circuit `graph` and `zkey`
    /// resources.
    ///
    /// On native targets both resources default to the single message-id circuit; on `wasm32`
    /// they must be supplied.
    #[builder(finish_fn = build)]
    pub fn stateful<State: ZerokitMerkleTree<Hasher = PoseidonHash>>(
        tree: State,
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
    ) -> RLN<Stateful<State>, ArkGroth16Backend<PoseidonHash>> {
        RLN::<Stateful<State>, _>::new(tree, ArkGroth16Backend::new(zkey, graph))
    }
}
