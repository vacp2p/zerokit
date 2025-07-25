use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, stdout, Cursor, Read, Write},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use color_eyre::{eyre::eyre, Report, Result};
use rln::{
    circuit::Fr,
    hashers::{hash_to_field_le, poseidon_hash},
    protocol::{keygen, prepare_prove_input, prepare_verify_input_le},
    public::{Endianness, RLN},
    utils::{fr_to_bytes_le, generate_input_buffer},
};

const MESSAGE_LIMIT: u32 = 1;

const TREEE_HEIGHT: usize = 20;

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
    identity_secret_hash: IdSecret,
    id_commitment: Fr,
}

impl Identity {
    fn new() -> Self {
        let (identity_secret_hash, id_commitment) = keygen();
        Identity {
            identity_secret_hash,
            id_commitment,
        }
    }
}

struct RLNSystem {
    rln: RLN,
    used_nullifiers: HashMap<[u8; 32], Vec<u8>>,
    local_identities: HashMap<usize, Identity>,
}

impl RLNSystem {
    fn new() -> Result<Self> {
        let mut resources: Vec<Vec<u8>> = Vec::new();
        let resources_path: PathBuf = format!("../rln/resources/tree_height_{TREEE_HEIGHT}").into();
        let filenames = ["rln_final.arkzkey", "graph.bin"];
        for filename in filenames {
            let fullpath = resources_path.join(Path::new(filename));
            let mut file = File::open(&fullpath)?;
            let metadata = std::fs::metadata(&fullpath)?;
            let mut output_buffer = vec![0; metadata.len() as usize];
            file.read_exact(&mut output_buffer)?;
            resources.push(output_buffer);
        }
        let rln = RLN::new_with_params(
            TREEE_HEIGHT,
            resources[0].clone(),
            resources[1].clone(),
            generate_input_buffer(),
            Endianness::LittleEndian,
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
            println!("+ Identity Secret Hash: {}", *identity.identity_secret_hash);
            println!("+ Identity Commitment: {}", identity.id_commitment);
            println!();
        }
    }

    fn register_user(&mut self) -> Result<usize> {
        let index = self.rln.leaves_set();
        let identity = Identity::new();

        let rate_commitment = poseidon_hash(&[identity.id_commitment, Fr::from(MESSAGE_LIMIT)]);
        let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
        match self.rln.set_next_leaf(&mut buffer) {
            Ok(_) => {
                println!("Registered User Index: {index}");
                println!("+ Identity secret hash: {}", *identity.identity_secret_hash);
                println!("+ Identity commitment: {},", identity.id_commitment);
                self.local_identities.insert(index, identity);
            }
            Err(_) => {
                println!("Maximum user limit reached: 2^{TREEE_HEIGHT}");
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
    ) -> Result<Vec<u8>> {
        let identity = match self.local_identities.get(&user_index) {
            Some(identity) => identity,
            None => return Err(eyre!("user index {user_index} not found")),
        };

        let serialized = prepare_prove_input(
            identity.identity_secret_hash.clone(),
            user_index,
            Fr::from(MESSAGE_LIMIT),
            Fr::from(message_id),
            external_nullifier,
            signal.as_bytes(),
        );
        let mut input_buffer = Cursor::new(serialized);
        let mut output_buffer = Cursor::new(Vec::new());
        self.rln
            .generate_rln_proof(&mut input_buffer, &mut output_buffer)?;

        println!("Proof generated successfully:");
        println!("+ User Index: {user_index}");
        println!("+ Message ID: {message_id}");
        println!("+ Signal: {signal}");

        Ok(output_buffer.into_inner())
    }

    fn verify_proof(&mut self, proof_data: Vec<u8>, signal: &str) -> Result<()> {
        let proof_with_signal = prepare_verify_input_le(proof_data.clone(), signal.as_bytes());
        let mut input_buffer = Cursor::new(proof_with_signal);

        match self.rln.verify_rln_proof(&mut input_buffer) {
            Ok(true) => {
                let nullifier = &proof_data[256..288];
                let nullifier_key: [u8; 32] = nullifier.try_into()?;

                if let Some(previous_proof) = self.used_nullifiers.get(&nullifier_key) {
                    self.handle_duplicate_message_id(previous_proof.clone(), proof_data)?;
                    return Ok(());
                }
                self.used_nullifiers.insert(nullifier_key, proof_data);
                println!("Message verified and accepted");
            }
            Ok(false) => {
                println!("Verification failed: message_id must be unique within the epoch and satisfy 0 <= message_id < MESSAGE_LIMIT: {MESSAGE_LIMIT}");
            }
            Err(err) => return Err(Report::new(err)),
        }
        Ok(())
    }

    fn handle_duplicate_message_id(
        &mut self,
        previous_proof: Vec<u8>,
        current_proof: Vec<u8>,
    ) -> Result<()> {
        let x = &current_proof[192..224];
        let y = &current_proof[224..256];

        let prev_x = &previous_proof[192..224];
        let prev_y = &previous_proof[224..256];
        if x == prev_x && y == prev_y {
            return Err(eyre!("this exact message and signal has already been sent"));
        }

        let mut proof1 = Cursor::new(previous_proof);
        let mut proof2 = Cursor::new(current_proof);
        let mut output = Cursor::new(Vec::new());

        match self
            .rln
            .recover_id_secret(&mut proof1, &mut proof2, &mut output)
        {
            Ok(_) => {
                let output_data = output.into_inner();
                let (leaked_identity_secret_hash, _) = IdSecret::from_bytes_le(&output_data);

                if let Some((user_index, identity)) = self
                    .local_identities
                    .iter()
                    .find(|(_, identity)| {
                        identity.identity_secret_hash == leaked_identity_secret_hash
                    })
                    .map(|(index, identity)| (*index, identity))
                {
                    let real_identity_secret_hash = identity.identity_secret_hash.clone();
                    if leaked_identity_secret_hash != real_identity_secret_hash {
                        Err(eyre!("identity secret hash mismatch: leaked_identity_secret_hash != real_identity_secret_hash"))
                    } else {
                        println!(
                            "DUPLICATE message ID detected! Reveal identity secret hash: {}",
                            *leaked_identity_secret_hash
                        );
                        self.local_identities.remove(&user_index);
                        self.rln.delete_leaf(user_index)?;
                        println!("User index {user_index} has been SLASHED");
                        Ok(())
                    }
                } else {
                    Err(eyre!("user identity secret hash ******** not found"))
                }
            }
            Err(err) => Err(eyre!("Failed to recover identity secret: {err}")),
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
                        Ok(proof) => {
                            if let Err(err) = rln_system.verify_proof(proof, &signal) {
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
