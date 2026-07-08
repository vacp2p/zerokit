use std::{marker::PhantomData, sync::Arc};

use ark_groth16::{prepare_verifying_key, PreparedVerifyingKey as ArkPreparedVerifyingKey};
use zerokit_utils::hasher::ZerokitHasher;

use super::{Curve, Graph, Zkey};
use crate::circuit::Fr;

/// The arkworks Groth16 proving backend over the RLN circuit with a specific hash function `H`.
#[derive(Debug, Clone)]
pub struct ArkGroth16Backend<H> {
    pub(crate) zkey: Arc<Zkey>,
    pub(crate) graph: Arc<Graph>,
    pub(crate) pvk: ArkPreparedVerifyingKey<Curve>,
    _hasher: PhantomData<H>,
}

impl<H> ArkGroth16Backend<H>
where
    H: ZerokitHasher<Scalar = Fr>,
{
    /// Creates a new backend from Groth16 circuit resources (`zkey` and `graph`).
    pub fn new(zkey: impl Into<Arc<Zkey>>, graph: impl Into<Arc<Graph>>) -> Self {
        let zkey = zkey.into();
        let graph = graph.into();
        let pvk = prepare_verifying_key(&zkey.0.vk);
        Self {
            zkey,
            graph,
            pvk,
            _hasher: PhantomData,
        }
    }
}
