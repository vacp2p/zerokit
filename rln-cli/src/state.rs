use std::io::Cursor;

use color_eyre::Result;
use rln::public::RLN;

use crate::config::{Config, InnerConfig};

#[derive(Default)]
pub(crate) struct State {
    pub rln: Option<RLN>,
}

impl State {
    pub(crate) fn load_state() -> Result<State> {
        let config = Config::load_config()?;
        let rln = if let Some(InnerConfig { tree_height, .. }) = config.inner {
            Some(RLN::new(tree_height, Cursor::new(config.as_bytes()), true)?)
        } else {
            None
        };
        Ok(State { rln })
    }
}
