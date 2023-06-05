use std::{fs::File, io::Read, path::Path};

use clap::Parser;
use color_eyre::{Report, Result};
use commands::Commands;
use rln::public::RLN;
use state::State;

mod commands;
mod state;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut state = State::default();

    match &cli.command {
        Some(Commands::New {
            tree_height,
            config,
        }) => {
            let resources = File::open(&config)?;
            state.rln = Some(RLN::new(*tree_height, resources)?);
            Ok(())
        }
        Some(Commands::NewWithParams {
            tree_height,
            config,
        }) => {
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
        Some(Commands::SetTree { tree_height }) => {
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_tree(*tree_height)?;
            Ok(())
        }
        Some(Commands::SetLeaf { index, file }) => {
            let input_data = File::open(&file)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_leaf(*index, input_data)?;
            Ok(())
        }
        Some(Commands::SetMultipleLeaves { index, file }) => {
            let input_data = File::open(&file)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_leaves_from(*index, input_data)?;
            Ok(())
        }
        Some(Commands::ResetMultipleLeaves { file }) => {
            let input_data = File::open(&file)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .init_tree_with_leaves(input_data)?;
            Ok(())
        }
        Some(Commands::SetNextLeaf { file }) => {
            let input_data = File::open(&file)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_next_leaf(input_data)?;
            Ok(())
        }
        Some(Commands::DeleteLeaf { index }) => {
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .delete_leaf(*index)?;
            Ok(())
        }
        Some(Commands::GetRoot) => {
            let writer = std::io::stdout();
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .get_root(writer)?;
            Ok(())
        }
        Some(Commands::GetProof { index }) => {
            let writer = std::io::stdout();
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .get_proof(*index, writer)?;
            Ok(())
        }
        Some(Commands::Prove { input }) => {
            let input_data = File::open(&input)?;
            let writer = std::io::stdout();
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .prove(input_data, writer)?;
            Ok(())
        }
        Some(Commands::Verify { file }) => {
            let input_data = File::open(&file)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .verify(input_data)?;
            Ok(())
        }
        Some(Commands::GenerateProof { input }) => {
            let input_data = File::open(&input)?;
            let writer = std::io::stdout();
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .generate_rln_proof(input_data, writer)?;
            Ok(())
        }
        Some(Commands::VerifyWithRoots { input, roots }) => {
            let input_data = File::open(&input)?;
            let roots_data = File::open(&roots)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .verify_with_roots(input_data, roots_data)?;
            Ok(())
        }
        None => Ok(()),
    }
}
