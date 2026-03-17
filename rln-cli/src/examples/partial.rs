use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, stdout, Read, Write},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use rln::prelude::{
    hash_to_field_le, keygen, poseidon_hash, recover_id_secret, Fr, IdSecret, PartialProof,
    PmtreeConfigBuilder, RLNPartialWitnessInput, RLNProofValues, RLNWitnessInput, RLN,
};
use zerokit_utils::pm_tree::Mode;

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
    partial_proofs: HashMap<usize, PartialProof>,
    external_nullifier: Fr,
}

impl RLNSystem {
    fn new(external_nullifier: Fr) -> Result<Self> {
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
            partial_proofs: HashMap::new(),
            external_nullifier,
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
                self.rebuild_partial_proofs()?;
            }
            Err(_) => {
                println!("Maximum user limit reached: 2^{TREE_DEPTH}");
            }
        };

        Ok(index)
    }

    fn rebuild_partial_proofs(&mut self) -> Result<()> {
        let indices: Vec<usize> = self.local_identities.keys().copied().collect();
        for user_index in indices {
            let identity = self.local_identities[&user_index].clone();
            let (path_elements, identity_path_index) = self.rln.get_merkle_proof(user_index)?;
            let witness = RLNWitnessInput::new(
                identity.identity_secret.clone(),
                Fr::from(MESSAGE_LIMIT),
                Fr::from(0u32),
                path_elements,
                identity_path_index,
                Fr::from(0u64),
                self.external_nullifier,
            )?;
            let partial_witness = RLNPartialWitnessInput::from(&witness);
            let partial_proof = self.rln.generate_partial_zk_proof(&partial_witness)?;
            self.partial_proofs.insert(user_index, partial_proof);
            println!("Pre-generated partial proof for User Index: {user_index}");
        }
        Ok(())
    }

    fn generate_and_verify_proof(
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

        let (path_elements, identity_path_index) = self.rln.get_merkle_proof(user_index)?;
        let x = hash_to_field_le(signal.as_bytes())?;

        let witness = RLNWitnessInput::new(
            identity.identity_secret.clone(),
            Fr::from(MESSAGE_LIMIT),
            Fr::from(message_id),
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )?;

        let partial_proof = match self.partial_proofs.get(&user_index) {
            Some(cached) => {
                println!("Using cached partial proof for User Index: {user_index}");
                cached.clone()
            }
            None => {
                let partial_witness = RLNPartialWitnessInput::from(&witness);
                self.rln.generate_partial_zk_proof(&partial_witness)?
            }
        };

        let (proof, proof_values) = self.rln.finish_rln_proof(&partial_proof, &witness)?;

        println!("Proof generated successfully:");
        println!("+ User Index: {user_index}");
        println!("+ Message ID: {message_id}");
        println!("+ Signal: {signal}");

        let verified = self.rln.verify_rln_proof(&proof, &proof_values, &x)?;
        if verified {
            println!("Proof verified successfully");
        }

        Ok(proof_values)
    }

    fn check_nullifier(&mut self, proof_values: RLNProofValues) -> Result<()> {
        if let Some(previous_proof_values) = self.used_nullifiers.get(proof_values.nullifier()) {
            self.handle_duplicate_nullifier(previous_proof_values.clone(), proof_values)?;
            return Ok(());
        }

        self.used_nullifiers
            .insert(*proof_values.nullifier(), proof_values);
        println!("Message verified and accepted");
        Ok(())
    }

    fn handle_duplicate_nullifier(
        &mut self,
        previous_proof_values: RLNProofValues,
        current_proof_values: RLNProofValues,
    ) -> Result<()> {
        if previous_proof_values.x() == current_proof_values.x()
            && previous_proof_values.y() == current_proof_values.y()
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
                        self.partial_proofs.remove(&user_index);
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
    let rln_epoch = hash_to_field_le(b"epoch")?;
    let rln_identifier = hash_to_field_le(b"rln-identifier")?;
    let external_nullifier = poseidon_hash(&[rln_epoch, rln_identifier]).unwrap();
    let mut rln_system = RLNSystem::new(external_nullifier)?;
    println!("RLN Partial Proof Example:");
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
                    match rln_system.generate_and_verify_proof(
                        user_index,
                        message_id,
                        &signal,
                        external_nullifier,
                    ) {
                        Ok(proof_values) => {
                            if let Err(err) = rln_system.check_nullifier(proof_values) {
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
    println!("  list                                        - List registered users");
    println!("  register                                    - Register a new user index");
    println!("  send -u <index> -m <message_id> -s <signal> - Send a message with partial proof");
    println!("  (example: send -u 0 -m 0 -s \"hello\")");
    println!("  clear                                       - Clear the screen");
    println!("  exit                                        - Exit the program");
}
