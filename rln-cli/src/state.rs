use std::io::Cursor;

use color_eyre::Result;
use rln::{circuit::TEST_TREE_DEPTH, public::RLN};
use serde_json::Value;

use crate::config::Config;

#[derive(Default)]
pub(crate) struct State {
    pub rln: Option<RLN>,
}

impl State {
    pub(crate) fn load_state() -> Result<State> {
        let config = Config::load_config()?;
        let rln = if let Some(tree_config) = config.tree_config {
            let config_json: Value = serde_json::from_str(&tree_config)?;
            let tree_depth = config_json["tree_depth"]
                .as_u64()
                .unwrap_or(TEST_TREE_DEPTH as u64);
            Some(RLN::new(
                tree_depth as usize,
                Cursor::new(tree_config.as_bytes()),
            )?)
        } else {
            None
        };
        Ok(State { rln })
    }
}
