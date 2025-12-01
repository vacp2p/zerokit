use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, stdout, Read, Write},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use rln::{
    circuit::Fr,
    hashers::{hash_to_field_le, poseidon_hash},
    pm_tree_adapter::PmtreeConfigBuilder,
    protocol::{keygen, recover_id_secret, RLNProofValues, RLNWitnessInput},
    public::RLN,
    utils::IdSecret,
};
use zerokit_utils::Mode;

const MESSAGE_LIMIT: u32 = 1;

const TREE_DEPTH: usize = 20;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    List,
    Register,
    Send {
        #[arg(short, long)]
        user_index: usize,
        #[arg(short, long)]
        message_id: u32,
        #[arg(short, long)]
        signal: String,
    },
    Clear,
    Exit,
}

#[derive(Debug, Clone)]
struct Identity {
    identity_secret: IdSecret,
    id_commitment: Fr,
}

impl Identity {
    fn new() -> Self {
        let (identity_secret, id_commitment) = keygen();
        Identity {
            identity_secret,
            id_commitment,
        }
    }
}

struct RLNSystem {
    rln: RLN,
    used_nullifiers: HashMap<Fr, RLNProofValues>,
    local_identities: HashMap<usize, Identity>,
}

impl RLNSystem {
    fn new() -> Result<Self> {
        let mut resources: Vec<Vec<u8>> = Vec::new();
        let resources_path: PathBuf = format!("../rln/resources/tree_depth_{TREE_DEPTH}").into();
        let filenames = ["rln_final.arkzkey", "graph.bin"];
        for filename in filenames {
            let fullpath = resources_path.join(Path::new(filename));
            let mut file = File::open(&fullpath)?;
            let metadata = std::fs::metadata(&fullpath)?;
            let mut output_buffer = vec![0; metadata.len() as usize];
            file.read_exact(&mut output_buffer)?;
            resources.push(output_buffer);
        }
        let tree_config = PmtreeConfigBuilder::new()
            .path("./database")
            .temporary(false)
            .cache_capacity(1073741824)
            .flush_every_ms(500)
            .mode(Mode::HighThroughput)
            .use_compression(false)
            .build()?;
        let rln = RLN::new_with_params(
            TREE_DEPTH,
            resources[0].clone(),
            resources[1].clone(),
            tree_config,
        )?;
        println!("RLN instance initialized successfully");
        Ok(RLNSystem {
            rln,
            used_nullifiers: HashMap::new(),
            local_identities: HashMap::new(),
        })
    }

    fn list_users(&self) {
        if self.local_identities.is_empty() {
            println!("No users registered yet.");
            return;
        }

        println!("Registered users:");
        for (index, identity) in &self.local_identities {
            println!("User Index: {index}");
            println!("+ Identity secret: {}", *identity.identity_secret);
            println!("+ Identity commitment: {}", identity.id_commitment);
            println!();
        }
    }

    fn register_user(&mut self) -> Result<usize> {
        let index = self.rln.leaves_set();
        let identity = Identity::new();

        let rate_commitment = poseidon_hash(&[identity.id_commitment, Fr::from(MESSAGE_LIMIT)]);
        match self.rln.set_next_leaf(rate_commitment) {
            Ok(_) => {
                println!("Registered User Index: {index}");
                println!("+ Identity secret: {}", *identity.identity_secret);
                println!("+ Identity commitment: {},", identity.id_commitment);
                self.local_identities.insert(index, identity);
            }
            Err(_) => {
                println!("Maximum user limit reached: 2^{TREE_DEPTH}");
            }
        };

        Ok(index)
    }

    fn generate_proof(
        &mut self,
        user_index: usize,
        message_id: u32,
        signal: &str,
        external_nullifier: Fr,
    ) -> Result<RLNProofValues> {
        let identity = match self.local_identities.get(&user_index) {
            Some(identity) => identity,
            None => return Err(format!("user index {user_index} not found").into()),
        };

        let (path_elements, identity_path_index) = self.rln.get_proof(user_index)?;
        let x = hash_to_field_le(signal.as_bytes());

        let witness = RLNWitnessInput::new(
            identity.identity_secret.clone(),
            Fr::from(MESSAGE_LIMIT),
            Fr::from(message_id),
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )?;

        let (_proof, proof_values) = self.rln.generate_rln_proof(&witness)?;

        println!("Proof generated successfully:");
        println!("+ User Index: {user_index}");
        println!("+ Message ID: {message_id}");
        println!("+ Signal: {signal}");

        Ok(proof_values)
    }

    fn verify_proof(&mut self, proof_values: RLNProofValues) -> Result<()> {
        if let Some(&previous_proof_values) = self.used_nullifiers.get(&proof_values.nullifier) {
            self.handle_duplicate_message_id(previous_proof_values, proof_values)?;
            return Ok(());
        }

        self.used_nullifiers
            .insert(proof_values.nullifier, proof_values);
        println!("Message verified and accepted");
        Ok(())
    }

    fn handle_duplicate_message_id(
        &mut self,
        previous_proof_values: RLNProofValues,
        current_proof_values: RLNProofValues,
    ) -> Result<()> {
        if previous_proof_values.x == current_proof_values.x
            && previous_proof_values.y == current_proof_values.y
        {
            return Err("this exact message and signal has already been sent".into());
        }

        match recover_id_secret(&previous_proof_values, &current_proof_values) {
            Ok(leaked_identity_secret) => {
                if let Some((user_index, identity)) = self
                    .local_identities
                    .iter()
                    .find(|(_, identity)| identity.identity_secret == leaked_identity_secret)
                    .map(|(index, identity)| (*index, identity))
                {
                    let real_identity_secret = identity.identity_secret.clone();
                    if leaked_identity_secret != real_identity_secret {
                        Err("Identity secret mismatch: leaked_identity_secret != real_identity_secret".into())
                    } else {
                        println!(
                            "DUPLICATE message ID detected! Reveal identity secret: {}",
                            *leaked_identity_secret
                        );
                        self.local_identities.remove(&user_index);
                        self.rln.delete_leaf(user_index)?;
                        println!("User index {user_index} has been SLASHED");
                        Ok(())
                    }
                } else {
                    Err("user identity secret ******** not found".into())
                }
            }
            Err(err) => Err(format!("Failed to recover identity secret: {err}").into()),
        }
    }
}

fn main() -> Result<()> {
    println!("Initializing RLN instance...");
    print!("\x1B[2J\x1B[1;1H");
    let mut rln_system = RLNSystem::new()?;
    let rln_epoch = hash_to_field_le(b"epoch");
    let rln_identifier = hash_to_field_le(b"rln-identifier");
    let external_nullifier = poseidon_hash(&[rln_epoch, rln_identifier]);
    println!("RLN Relay Example:");
    println!("Message Limit: {MESSAGE_LIMIT}");
    println!("----------------------------------");
    println!();
    show_commands();
    loop {
        print!("\n> ");
        stdout().flush()?;
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        let args = std::iter::once("").chain(trimmed.split_whitespace());

        match Cli::try_parse_from(args) {
            Ok(cli) => match cli.command {
                Commands::List => {
                    rln_system.list_users();
                }
                Commands::Register => {
                    rln_system.register_user()?;
                }
                Commands::Send {
                    user_index,
                    message_id,
                    signal,
                } => {
                    match rln_system.generate_proof(
                        user_index,
                        message_id,
                        &signal,
                        external_nullifier,
                    ) {
                        Ok(proof_values) => {
                            if let Err(err) = rln_system.verify_proof(proof_values) {
                                println!("Verification error: {err}");
                            };
                        }
                        Err(err) => {
                            println!("Proof generation error: {err}");
                        }
                    }
                }
                Commands::Clear => {
                    print!("\x1B[2J\x1B[1;1H");
                    show_commands();
                }
                Commands::Exit => {
                    break;
                }
            },
            Err(err) => {
                eprintln!("Command error: {err}");
            }
        }
    }
    Ok(())
}

fn show_commands() {
    println!("Available commands:");
    println!("  list                                        - List registered users");
    println!("  register                                    - Register a new user index");
    println!("  send -u <index> -m <message_id> -s <signal> - Send a message with proof");
    println!("  clear                                       - Clear the screen");
    println!("  exit                                        - Exit the program");
}
