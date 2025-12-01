use std::path::PathBuf;

use clap::Subcommand;
use rln::circuit::DEFAULT_TREE_DEPTH;

#[derive(Subcommand)]
pub(crate) enum Commands {
    New {
        #[arg(short, long, default_value_t = DEFAULT_TREE_DEPTH)]
        tree_depth: usize,
    },
    NewWithParams {
        #[arg(short, long, default_value_t = DEFAULT_TREE_DEPTH)]
        tree_depth: usize,
        #[arg(short, long, default_value = "../rln/resources/tree_depth_20")]
        resources_path: PathBuf,
    },
    SetTree {
        #[arg(short, long, default_value_t = DEFAULT_TREE_DEPTH)]
        tree_depth: usize,
    },
    SetLeaf {
        #[arg(short, long)]
        index: usize,
        #[arg(short, long)]
        input: PathBuf,
    },
    SetMultipleLeaves {
        #[arg(short, long)]
        index: usize,
        #[arg(short, long)]
        input: PathBuf,
    },
    ResetMultipleLeaves {
        #[arg(short, long)]
        input: PathBuf,
    },
    SetNextLeaf {
        #[arg(short, long)]
        input: PathBuf,
    },
    DeleteLeaf {
        #[arg(short, long)]
        index: usize,
    },
    GetRoot,
    GetProof {
        #[arg(short, long)]
        index: usize,
    },
    Prove {
        #[arg(short, long)]
        input: PathBuf,
    },
    Verify {
        #[arg(short, long)]
        input: PathBuf,
    },
    GenerateProof {
        #[arg(short, long)]
        input: PathBuf,
    },
    VerifyWithRoots {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        roots: PathBuf,
    },
}
