use std::{fs::File, io::Read, path::PathBuf};

use color_eyre::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RLN_CONFIG_PATH: &str = "RLN_CONFIG_PATH";

#[derive(Serialize, Deserialize)]
pub(crate) struct Config {
    pub tree_config: Option<String>,
}

impl Config {
    pub(crate) fn load_config() -> Result<Config> {
        match std::env::var(RLN_CONFIG_PATH) {
            Ok(env) => {
                let path = PathBuf::from(env);
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let tree_config: Value = serde_json::from_str(&contents)?;
                println!("Initializing RLN with custom config");
                Ok(Config {
                    tree_config: Some(tree_config.to_string()),
                })
            }
            Err(_) => Ok(Config { tree_config: None }),
        }
    }
}
