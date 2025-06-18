#![cfg(feature = "stateless")]
use std::{
    collections::HashMap,
    io::{stdin, stdout, Cursor, Write},
};

use clap::{Parser, Subcommand};
use color_eyre::{eyre::eyre, Result};
use rln::{
    circuit::{Fr, TEST_TREE_HEIGHT},
    hashers::{hash_to_field, poseidon_hash},
    poseidon_tree::PoseidonTree,
    protocol::{keygen, prepare_verify_input, rln_witness_from_values, serialize_witness},
    public::RLN,
    utils::{bytes_le_to_fr, fr_to_bytes_le},
};
use rln::utils::IdSecret;
use zerokit_utils::ZerokitMerkleTree;

const MESSAGE_LIMIT: u32 = 1;

type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

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
    tree: PoseidonTree,
    used_nullifiers: HashMap<[u8; 32], Vec<u8>>,
    local_identities: HashMap<usize, Identity>,
}

impl RLNSystem {
    fn new() -> Result<Self> {
        let rln = RLN::new()?;
        let default_leaf = Fr::from(0);
        let tree = PoseidonTree::new(
            TEST_TREE_HEIGHT,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )?;

        Ok(RLNSystem {
            rln,
            tree,
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
            println!("+ Identity Secret Hash: ********");
            println!("+ Identity Commitment: {}", identity.id_commitment);
            println!();
        }
    }

    fn register_user(&mut self) -> Result<usize> {
        let index = self.tree.leaves_set();
        let identity = Identity::new();

        let rate_commitment = poseidon_hash(&[identity.id_commitment, Fr::from(MESSAGE_LIMIT)]);
        self.tree.update_next(rate_commitment)?;

        println!("Registered User Index: {index}");
        println!("+ Identity secret hash: ********");
        println!("+ Identity commitment: {}", identity.id_commitment);

        self.local_identities.insert(index, identity);
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

        let merkle_proof = self.tree.proof(user_index)?;
        let x = hash_to_field(signal.as_bytes());

        let rln_witness = rln_witness_from_values(
            identity.identity_secret_hash.clone(),
            &merkle_proof,
            x,
            external_nullifier,
            Fr::from(MESSAGE_LIMIT),
            Fr::from(message_id),
        )?;

        let serialized = serialize_witness(&rln_witness)?;
        let mut input_buffer = Cursor::new(serialized);
        let mut output_buffer = Cursor::new(Vec::new());

        self.rln
            .generate_rln_proof_with_witness(&mut input_buffer, &mut output_buffer)?;

        println!("Proof generated successfully:");
        println!("+ User Index: {user_index}");
        println!("+ Message ID: {message_id}");
        println!("+ Signal: {signal}");

        Ok(output_buffer.into_inner())
    }

    fn verify_proof(&mut self, proof_data: Vec<u8>, signal: &str) -> Result<()> {
        let proof_with_signal = prepare_verify_input(proof_data.clone(), signal.as_bytes());
        let mut input_buffer = Cursor::new(proof_with_signal);

        let root = self.tree.root();
        let roots_serialized = fr_to_bytes_le(&root);
        let mut roots_buffer = Cursor::new(roots_serialized);

        match self
            .rln
            .verify_with_roots(&mut input_buffer, &mut roots_buffer)
        {
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
            Err(err) => return Err(err.into()),
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
                        println!("DUPLICATE message ID detected! Reveal identity secret hash: ********");
                        self.local_identities.remove(&user_index);
                        println!("User index {user_index} has been SLASHED");
                        Ok(())
                    }
                } else {
                    Err(eyre!(
                        "user identity secret hash ******** not found"
                    ))
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
    let rln_epoch = hash_to_field(b"epoch");
    let rln_identifier = hash_to_field(b"rln-identifier");
    let external_nullifier = poseidon_hash(&[rln_epoch, rln_identifier]);
    println!("RLN Stateless Relay Example:");
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
