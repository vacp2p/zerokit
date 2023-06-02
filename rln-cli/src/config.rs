use color_eyre::Result;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::PathBuf};

pub const RLN_STATE_PATH: &str = "RLN_STATE_PATH";

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Config {
    pub inner: Option<InnerConfig>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct InnerConfig {
    pub file: PathBuf,
    pub tree_height: usize,
}

impl Config {
    pub(crate) fn load_config() -> Result<Config> {
        let path = PathBuf::from(std::env::var(RLN_STATE_PATH)?);

        let mut file = File::open(path)?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let state: Config = serde_json::from_str(&contents)?;
        Ok(state)
    }
}
