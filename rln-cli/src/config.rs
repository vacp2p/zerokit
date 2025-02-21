use std::{fs::File, io::Read, path::PathBuf};

use color_eyre::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RLN_CONFIG_PATH: &str = "RLN_CONFIG_PATH";

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Config {
    pub inner: Option<InnerConfig>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct InnerConfig {
    pub tree_height: usize,
    pub tree_config: Value,
}

impl Config {
    pub(crate) fn load_config() -> Result<Config> {
        match std::env::var(RLN_CONFIG_PATH) {
            Ok(env) => {
                let path = PathBuf::from(env);
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let inner: InnerConfig = serde_json::from_str(&contents)?;
                Ok(Config { inner: Some(inner) })
            }
            Err(_) => Ok(Config::default()),
        }
    }

    pub(crate) fn as_bytes(&self) -> Vec<u8> {
        serde_json::to_string(&self.inner).unwrap().into_bytes()
    }
}
