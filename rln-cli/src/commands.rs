use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Commands {
    New {
        tree_height: usize,
        /// Sets a custom config file
        #[arg(short, long)]
        config: PathBuf,
    },
    NewWithParams {
        tree_height: usize,
        /// Sets a custom config file
        #[arg(short, long)]
        config: PathBuf,
    },
    SetTree {
        tree_height: usize,
    },
}
