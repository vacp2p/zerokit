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
    SetLeaf {
        index: usize,
        #[arg(short, long)]
        file: PathBuf,
    },
    SetMultipleLeaves {
        index: usize,
        #[arg(short, long)]
        file: PathBuf,
    },
    ResetMultipleLeaves {
        #[arg(short, long)]
        file: PathBuf,
    },
    SetNextLeaf {
        #[arg(short, long)]
        file: PathBuf,
    },
    DeleteLeaf {
        index: usize,
    },
    GetRoot {
        #[arg(short, long)]
        file: PathBuf,
    },
    GetProof {
        index: usize,
        #[arg(short, long)]
        file: PathBuf,
    },
    Prove {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Verify {
        #[arg(short, long)]
        file: PathBuf,
    },
    GenerateProof {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    VerifyWithRoots {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        roots: PathBuf,
    },
}
