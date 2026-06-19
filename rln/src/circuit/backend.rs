use std::sync::Arc;

use ark_groth16::{prepare_verifying_key, PreparedVerifyingKey as ArkPreparedVerifyingKey};

use super::{Curve, Graph, Zkey};

#[derive(Clone, Debug)]
pub struct ArkGroth16Backend {
    pub(crate) zkey: Arc<Zkey>,
    pub(crate) graph: Arc<Graph>,
    pub(crate) pvk: ArkPreparedVerifyingKey<Curve>,
}

impl ArkGroth16Backend {
    pub fn new(zkey: impl Into<Arc<Zkey>>, graph: impl Into<Arc<Graph>>) -> Self {
        let zkey = zkey.into();
        let graph = graph.into();
        let pvk = prepare_verifying_key(&zkey.0.vk);
        Self { zkey, graph, pvk }
    }
}
