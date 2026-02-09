#![cfg(feature = "multi-message-id")]

use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, stdout, Read, Write},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use rln::prelude::{
    hash_to_field_le, keygen, poseidon_hash, recover_id_secret, Fr, IdSecret, PmtreeConfigBuilder,
    RLNProofValues, RLNWitnessInput, DEFAULT_TREE_DEPTH, RLN,
};
use zerokit_utils::pm_tree::Mode;

const MESSAGE_LIMIT: u32 = 10;

const TREE_DEPTH: usize = DEFAULT_TREE_DEPTH;

const MESSAGE_ID_NUMBER: usize = 4;

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
        message_ids: String,
        #[arg(long)]
        selector: String,
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
        let (identity_secret, id_commitment) = keygen().unwrap();
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
        let resources_path: PathBuf =
            format!("../rln/resources/tree_depth_{TREE_DEPTH}/multi_message_id").into();
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
        println!("RLN multi-message-id instance initialized successfully");
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

        let rate_commitment =
            poseidon_hash(&[identity.id_commitment, Fr::from(MESSAGE_LIMIT)]).unwrap();
        match self.rln.set_next_leaf(rate_commitment) {
            Ok(_) => {
                println!("Registered User Index: {index}");
                println!("+ Identity secret: {}", *identity.identity_secret);
                println!("+ Identity commitment: {}", identity.id_commitment);
                self.local_identities.insert(index, identity);
            }
            Err(_) => {
                println!("Maximum user limit reached: 2^{TREE_DEPTH}");
            }
        };

        Ok(index)
    }

    fn parse_message_ids(input: &str) -> Result<Vec<Fr>> {
        let ids: Vec<Fr> = input
            .split(',')
            .map(|s| {
                let id: u32 = s.trim().parse()?;
                Ok(Fr::from(id))
            })
            .collect::<Result<Vec<Fr>>>()?;
        if ids.len() != MESSAGE_ID_NUMBER as usize {
            return Err(format!(
                "expected {MESSAGE_ID_NUMBER} message IDs, got {}",
                ids.len()
            )
            .into());
        }
        Ok(ids)
    }

    fn parse_selector(input: &str) -> Result<Vec<bool>> {
        let selector: Vec<bool> = input
            .split(',')
            .map(|s| match s.trim() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                other => Err(format!("invalid selector value: '{other}'")),
            })
            .collect::<std::result::Result<Vec<bool>, String>>()?;
        if selector.len() != MESSAGE_ID_NUMBER {
            return Err(format!(
                "expected {MESSAGE_ID_NUMBER} selector values, got {}",
                selector.len()
            )
            .into());
        }
        Ok(selector)
    }

    fn generate_and_verify_proof(
        &mut self,
        user_index: usize,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
        signal: &str,
        external_nullifier: Fr,
    ) -> Result<RLNProofValues> {
        let identity = match self.local_identities.get(&user_index) {
            Some(identity) => identity,
            None => return Err(format!("user index {user_index} not found").into()),
        };

        let (path_elements, identity_path_index) = self.rln.get_merkle_proof(user_index)?;
        let x = hash_to_field_le(signal.as_bytes())?;

        let witness = RLNWitnessInput::new(
            identity.identity_secret.clone(),
            Fr::from(MESSAGE_LIMIT),
            None,
            Some(message_ids.clone()),
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            Some(selector_used.clone()),
        )?;

        let (proof, proof_values) = self.rln.generate_rln_proof(&witness)?;

        let active_count = selector_used.iter().filter(|&&s| s).count();
        println!("Proof generated successfully:");
        println!("+ User Index: {user_index}");
        println!("+ Active message slots: {active_count}/{MESSAGE_ID_NUMBER}");
        println!("+ Signal: {signal}");

        let verified = self.rln.verify_rln_proof(&proof, &proof_values, &x)?;
        if verified {
            println!("Proof verified successfully");
        }

        Ok(proof_values)
    }

    fn check_nullifiers(&mut self, proof_values: RLNProofValues) -> Result<()> {
        let nullifiers = match &proof_values.nullifiers {
            Some(nullifiers) => nullifiers.clone(),
            None => return Err("no nullifiers in proof values".into()),
        };
        let selector = match &proof_values.selector_used {
            Some(selector) => selector.clone(),
            None => return Err("no selector_used in proof values".into()),
        };

        for (i, (nullifier, active)) in nullifiers.iter().zip(selector.iter()).enumerate() {
            if !active {
                continue;
            }

            if let Some(previous_proof_values) = self.used_nullifiers.get(nullifier) {
                self.handle_duplicate_nullifier(previous_proof_values.clone(), proof_values, i)?;
                return Ok(());
            }
        }

        for (nullifier, active) in nullifiers.iter().zip(selector.iter()) {
            if *active {
                self.used_nullifiers
                    .insert(*nullifier, proof_values.clone());
            }
        }
        println!("Message verified and accepted");
        Ok(())
    }

    fn handle_duplicate_nullifier(
        &mut self,
        previous_proof_values: RLNProofValues,
        current_proof_values: RLNProofValues,
        duplicated_slot: usize,
    ) -> Result<()> {
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
                            "DUPLICATE nullifier detected at slot {}! Reveal identity secret: {}",
                            duplicated_slot, *leaked_identity_secret
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
    println!("Initializing RLN multi-message-id instance...");
    print!("\x1B[2J\x1B[1;1H");
    let mut rln_system = RLNSystem::new()?;
    let rln_epoch = hash_to_field_le(b"epoch")?;
    let rln_identifier = hash_to_field_le(b"rln-identifier")?;
    let external_nullifier = poseidon_hash(&[rln_epoch, rln_identifier]).unwrap();
    println!("RLN Multi-Message-ID Relay Example:");
    println!("Message Limit: {MESSAGE_LIMIT}");
    println!("Message Slots: {MESSAGE_ID_NUMBER}");
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
                    message_ids,
                    selector,
                    signal,
                } => {
                    let message_ids = match RLNSystem::parse_message_ids(&message_ids) {
                        Ok(ids) => ids,
                        Err(err) => {
                            println!("Invalid message_ids: {err}");
                            continue;
                        }
                    };
                    let selector_used = match RLNSystem::parse_selector(&selector) {
                        Ok(sel) => sel,
                        Err(err) => {
                            println!("Invalid selector: {err}");
                            continue;
                        }
                    };
                    match rln_system.generate_and_verify_proof(
                        user_index,
                        message_ids,
                        selector_used,
                        &signal,
                        external_nullifier,
                    ) {
                        Ok(proof_values) => {
                            if let Err(err) = rln_system.check_nullifiers(proof_values) {
                                println!("Check nullifier error: {err}");
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
    println!(
        "  list                                                          - List registered users"
    );
    println!("  register                                                      - Register a new user index");
    println!("  send -u <index> -m <ids> --selector <bools> -s <signal>       - Send a message with proof");
    println!("  (example: send -u 0 -m 0,1,2,3 --selector 1,1,0,0 -s \"hello\")");
    println!("  clear                                                         - Clear the screen");
    println!("  exit                                                          - Exit the program");
}
