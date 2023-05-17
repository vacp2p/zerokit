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

#[derive(Subcommand)]
enum Commands {
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
}

fn main() -> Result<()>{
    let cli = Cli::parse();

    let mut state = State::default();

    match &cli.command {
        Some(Commands::New { tree_height, config }) => {
            let resources = File::open(&config).expect("no file found");
            state.rln = Some(RLN::new(*tree_height, resources)?);
            Ok(())
        }
        Some(Commands::NewWithParams { tree_height, config }) => {
            let mut resources: Vec<Vec<u8>> = Vec::new();
            for filename in ["rln.wasm", "rln_final.zkey", "verification_key.json"] {
                let fullpath = config.join(Path::new(filename));
                let mut file = File::open(&fullpath)?;
                let metadata = std::fs::metadata(&fullpath)?;
                let mut buffer = vec![0; metadata.len() as usize];
                file.read_exact(&mut buffer)?;
                resources.push(buffer);
            }
            state.rln = Some(RLN::new_with_params(
                *tree_height,
                resources[0].clone(),
                resources[1].clone(),
                resources[2].clone(),
            )?);
            Ok(())
        }
        None => {Ok(())}
    }
}