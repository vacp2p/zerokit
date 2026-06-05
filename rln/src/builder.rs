use zerokit_utils::merkle_tree::{Hasher, ZerokitMerkleTree, ZerokitMerkleTreeError};

#[cfg(not(target_arch = "wasm32"))]
use crate::circuit::{graph_multi_v1, graph_single_v1, zkey_multi_v1, zkey_single_v1};
use crate::{
    circuit::{graph_from_raw, zkey_from_raw, ArkGroth16Backend, Fr},
    error::InitErrorV3,
    protocol::{Stateful, Stateless},
    public::RLNV3,
};

pub struct RLNBuilder<ZKP> {
    zkp: ZKP,
}

impl<ZKP> RLNBuilder<ZKP> {
    pub fn new(zkp: ZKP) -> Self {
        Self { zkp }
    }

    pub fn build_stateless(self) -> RLNV3<Stateless, ZKP> {
        RLNV3::<Stateless, ZKP>::new(self.zkp)
    }

    pub fn build_stateful<T>(self, tree: T) -> RLNV3<Stateful<T>, ZKP> {
        RLNV3::<Stateful<T>, ZKP>::new(tree, self.zkp)
    }

    pub fn build_stateful_default<T>(
        self,
        depth: usize,
    ) -> Result<RLNV3<Stateful<T>, ZKP>, ZerokitMerkleTreeError>
    where
        T: ZerokitMerkleTree,
    {
        let tree = <T as ZerokitMerkleTree>::default(depth)?;
        Ok(self.build_stateful(tree))
    }

    pub fn build_stateful_with_config<T>(
        self,
        depth: usize,
        config: T::Config,
    ) -> Result<RLNV3<Stateful<T>, ZKP>, ZerokitMerkleTreeError>
    where
        T: ZerokitMerkleTree,
        T::Hasher: Hasher<Fr = Fr>,
    {
        let tree = T::new(depth, <T::Hasher as Hasher>::default_leaf(), config)?;
        Ok(self.build_stateful(tree))
    }
}

impl RLNBuilder<ArkGroth16Backend> {
    pub fn from_raw(zkey_data: Vec<u8>, graph_data: Vec<u8>) -> Result<Self, InitErrorV3> {
        let zkey = zkey_from_raw(&zkey_data)?;
        let graph = graph_from_raw(&graph_data, None, None)?;
        Ok(Self::new(ArkGroth16Backend::new(zkey, graph)))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_defaults_single() -> Self {
        Self::new(ArkGroth16Backend::new(
            zkey_single_v1().to_owned(),
            graph_single_v1().to_owned(),
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_defaults_multi() -> Self {
        Self::new(ArkGroth16Backend::new(
            zkey_multi_v1().to_owned(),
            graph_multi_v1().to_owned(),
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_json(json: &str) -> Result<Self, InitErrorV3> {
        let config: BuilderJsonConfig = serde_json::from_str(json)?;
        let zkey_data = std::fs::read(&config.zkey_path)?;
        let graph_data = std::fs::read(&config.graph_path)?;
        let zkey = zkey_from_raw(&zkey_data)?;
        let graph = graph_from_raw(&graph_data, config.tree_depth, None)?;
        Ok(Self::new(ArkGroth16Backend::new(zkey, graph)))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Deserialize)]
struct BuilderJsonConfig {
    zkey_path: String,
    graph_path: String,
    #[serde(default)]
    tree_depth: Option<usize>,
}
