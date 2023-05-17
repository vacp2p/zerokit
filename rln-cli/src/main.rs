use std::{path::{PathBuf, Path}, fs::File, io::Read};

use clap::{Parser, Subcommand};
use rln::public::RLN;
use color_eyre::Result;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Default)]
struct State<'a> {
    rln: Option<RLN<'a>>,
}
