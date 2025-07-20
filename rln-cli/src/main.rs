use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use clap::Parser;
use color_eyre::{eyre::Report, Result};
use commands::Commands;
use config::{Config, InnerConfig};
use rln::{
    public::RLN,
    utils::{bytes_le_to_fr, bytes_le_to_vec_fr},
};
use serde_json::json;
use state::State;

mod commands;
mod config;
mod state;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut state = match &cli.command {
        Some(Commands::New { .. }) | Some(Commands::NewWithParams { .. }) => State::default(),
        _ => State::load_state()?,
    };

    match cli.command {
        Some(Commands::New { tree_height }) => {
            let config = Config::load_config()?;
            state.rln = if let Some(InnerConfig { tree_height, .. }) = config.inner {
                println!("Initializing RLN with custom config");
                Some(RLN::new(tree_height, Cursor::new(config.as_bytes()))?)
            } else {
                println!("Initializing RLN with default config");
                Some(RLN::new(tree_height, Cursor::new(json!({}).to_string()))?)
            };
            Ok(())
        }
        Some(Commands::NewWithParams {
            tree_height,
            resources_path,
        }) => {
            let mut resources: Vec<Vec<u8>> = Vec::new();
            let filenames = ["rln_final.arkzkey", "graph.bin"];
            for filename in filenames {
                let fullpath = resources_path.join(Path::new(filename));
                let mut file = File::open(&fullpath)?;
                let metadata = std::fs::metadata(&fullpath)?;
                let mut output_buffer = vec![0; metadata.len() as usize];
                file.read_exact(&mut output_buffer)?;
                resources.push(output_buffer);
            }
            let config = Config::load_config()?;
            if let Some(InnerConfig {
                tree_height,
                tree_config,
            }) = config.inner
            {
                println!("Initializing RLN with custom config");
                state.rln = Some(RLN::new_with_params(
                    tree_height,
                    resources[0].clone(),
                    resources[1].clone(),
                    Cursor::new(tree_config.to_string().as_bytes()),
                )?)
            } else {
                println!("Initializing RLN with default config");
                state.rln = Some(RLN::new_with_params(
                    tree_height,
                    resources[0].clone(),
                    resources[1].clone(),
                    Cursor::new(json!({}).to_string()),
                )?)
            };
            Ok(())
        }
        Some(Commands::SetTree { tree_height }) => {
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_tree(tree_height)?;
            Ok(())
        }
        Some(Commands::SetLeaf { index, input }) => {
            let input_data = File::open(input)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_leaf(index, input_data)?;
            Ok(())
        }
        Some(Commands::SetMultipleLeaves { index, input }) => {
            let input_data = File::open(input)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .set_leaves_from(index, input_data)?;
            Ok(())
        }
        Some(Commands::ResetMultipleLeaves { input }) => {
            let input_data = File::open(input)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .init_tree_with_leaves(input_data)?;
            Ok(())
        }
        Some(Commands::SetNextLeaf { input }) => {
            let input_data = File::open(input)?;
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
                .delete_leaf(index)?;
            Ok(())
        }
        Some(Commands::Prove { input }) => {
            let input_data = File::open(input)?;
            let mut output_buffer = Cursor::new(Vec::<u8>::new());
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .prove(input_data, &mut output_buffer)?;
            let proof = output_buffer.into_inner();
            println!("proof: {proof:?}");
            Ok(())
        }
        Some(Commands::Verify { input }) => {
            let input_data = File::open(input)?;
            let verified = state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .verify(input_data)?;
            println!("verified: {verified:?}");
            Ok(())
        }
        Some(Commands::GenerateProof { input }) => {
            let input_data = File::open(input)?;
            let mut output_buffer = Cursor::new(Vec::<u8>::new());
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .generate_rln_proof(input_data, &mut output_buffer)?;
            let proof = output_buffer.into_inner();
            println!("proof: {proof:?}");
            Ok(())
        }
        Some(Commands::VerifyWithRoots { input, roots }) => {
            let input_data = File::open(input)?;
            let roots_data = File::open(roots)?;
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .verify_with_roots(input_data, roots_data)?;
            Ok(())
        }
        Some(Commands::GetRoot) => {
            let mut output_buffer = Cursor::new(Vec::<u8>::new());
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .get_root(&mut output_buffer)
                .unwrap();
            let (root, _) = bytes_le_to_fr(&output_buffer.into_inner());
            println!("root: {root}");
            Ok(())
        }
        Some(Commands::GetProof { index }) => {
            let mut output_buffer = Cursor::new(Vec::<u8>::new());
            state
                .rln
                .ok_or(Report::msg("no RLN instance initialized"))?
                .get_proof(index, &mut output_buffer)?;
            let output_buffer_inner = output_buffer.into_inner();
            let (path_elements, _) = bytes_le_to_vec_fr(&output_buffer_inner)?;
            for (index, element) in path_elements.iter().enumerate() {
                println!("path element {index}: {element}");
            }
            Ok(())
        }
        None => Ok(()),
    }
}
