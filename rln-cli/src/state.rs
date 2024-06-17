use color_eyre::Result;
use rln::public::RLN;
use std::fs::File;

use crate::config::{Config, InnerConfig};

#[derive(Default)]
pub(crate) struct State {
    pub rln: Option<RLN>,
}

impl State {
    pub(crate) fn load_state() -> Result<State> {
        let config = Config::load_config()?;
        let rln = if let Some(InnerConfig { file, tree_height }) = config.inner {
            let resources = File::open(&file)?;
            Some(RLN::new(tree_height, resources)?)
        } else {
            None
        };
        Ok(State { rln })
    }
}
