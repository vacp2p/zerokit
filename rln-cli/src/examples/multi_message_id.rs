use std::{
    collections::HashMap,
    io::{stdin, stdout, Write},
};

use clap::{Parser, Subcommand};
use rln::prelude::{
    default_graph_multi, default_zkey_multi, hash_to_field_le, keygen, poseidon_hash,
    ArkGroth16Backend, Fr, IdSecret, PmTree, PmTreeConfig, PoseidonHash, RLNBuilder,
    RLNProofValuesV3, RLNWitnessInputV3, RecoverSecret, Stateful, RLNV3,
};
use zerokit_utils::merkle_tree::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree};

const MESSAGE_LIMIT: u32 = 4;

const TREE_DEPTH: usize = 20;

const MAX_OUT: usize = 4;

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
        let (identity_secret, id_commitment) = keygen();
        Identity {
            identity_secret,
            id_commitment,
        }
    }
}

struct RLNSystem {
    rln: RLNV3<Stateful<PmTree>, ArkGroth16Backend>,
    used_nullifiers: HashMap<Fr, RLNProofValuesV3>,
    local_identities: HashMap<usize, Identity>,
}

impl RLNSystem {
    fn new() -> Result<Self> {
        let pm_tree_config: PmTreeConfig = r#"{
            "path": "./database",
            "temporary": false,
            "cache_capacity": 1073741824,
            "flush_every_ms": 500,
            "mode": "HighThroughput",
            "use_compression": false,
            "tree_depth": 20
        }"#
        .parse()?;
        let pm_tree = <PmTree as ZerokitMerkleTree>::new(
            TREE_DEPTH,
            PoseidonHash::default_leaf(),
            pm_tree_config,
        )?;
        let rln = RLNBuilder::stateful()
            .tree(pm_tree)
            .graph(default_graph_multi().clone())
            .zkey(default_zkey_multi().clone())
            .build();
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
            println!("User: {index}");
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
                println!("Registered user: {index}");
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

    fn parse_message_ids(&self, input: &str) -> Result<Vec<Fr>> {
        let ids: Vec<Fr> = input
            .split(',')
            .map(|s| {
                let id: u32 = s.trim().parse()?;
                Ok(Fr::from(id))
            })
            .collect::<Result<Vec<Fr>>>()?;
        if ids.len() != MAX_OUT {
            return Err(format!("expected {} message IDs, got {}", MAX_OUT, ids.len()).into());
        }
        Ok(ids)
    }

    fn parse_selector(&self, input: &str) -> Result<Vec<bool>> {
        let selector: Vec<bool> = input
            .split(',')
            .map(|s| match s.trim() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                other => Err(format!("invalid selector value: '{other}'")),
            })
            .collect::<std::result::Result<Vec<bool>, String>>()?;
        if selector.len() != MAX_OUT {
            return Err(format!(
                "expected {} selector values, got {}",
                MAX_OUT,
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
    ) -> Result<RLNProofValuesV3> {
        let identity = match self.local_identities.get(&user_index) {
            Some(identity) => identity,
            None => return Err(format!("User {user_index} not found").into()),
        };

        let merkle_proof = self.rln.get_merkle_proof(user_index)?;
        let x = hash_to_field_le(signal.as_bytes());

        let witness = RLNWitnessInputV3::new_multi()
            .identity_secret(identity.identity_secret.clone())
            .user_message_limit(Fr::from(MESSAGE_LIMIT))
            .path_elements(merkle_proof.get_path_elements())
            .identity_path_index(merkle_proof.get_path_index())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_ids(message_ids)
            .selector_used(selector_used.clone())
            .build()?;

        let (proof, proof_values) = self.rln.generate_proof(&witness)?;
        let active_count = selector_used.iter().filter(|&&s| s).count();
        println!("Proof generated successfully:");
        println!("+ User: {user_index}");
        println!("+ Active message slots: {active_count}/{}", MAX_OUT);
        println!("+ Signal: {signal}");

        let verified = self.rln.verify(&proof, &proof_values)?;
        if verified {
            println!("Proof verified successfully");
        }

        Ok(proof_values)
    }

    fn check_nullifier(&mut self, proof_values: RLNProofValuesV3) -> Result<()> {
        if let (Some(nullifiers), Some(selector)) =
            (proof_values.nullifiers(), proof_values.selector_used())
        {
            for (i, (nullifier, active)) in nullifiers.iter().zip(selector.iter()).enumerate() {
                if !active {
                    continue;
                }

                if let Some(previous_proof_values) = self.used_nullifiers.get(nullifier) {
                    self.handle_duplicate_nullifier(
                        previous_proof_values.clone(),
                        proof_values,
                        i,
                    )?;
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
        }

        Ok(())
    }

    fn handle_duplicate_nullifier(
        &mut self,
        previous_proof_values: RLNProofValuesV3,
        current_proof_values: RLNProofValuesV3,
        duplicated_slot: usize,
    ) -> Result<()> {
        match previous_proof_values.recover_secret(&current_proof_values) {
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
                        println!("User {user_index} has been SLASHED");
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
    let rln_epoch = hash_to_field_le(b"epoch");
    let rln_identifier = hash_to_field_le(b"rln-identifier");
    let external_nullifier = poseidon_hash(&[rln_epoch, rln_identifier]);
    println!("RLN Multi-Message-ID Example:");
    println!("Message Limit: {MESSAGE_LIMIT}");
    println!("Message Slots: 1 - {MAX_OUT}");
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
                    let message_ids = match rln_system.parse_message_ids(&message_ids) {
                        Ok(ids) => ids,
                        Err(err) => {
                            println!("Invalid message_ids: {err}");
                            continue;
                        }
                    };
                    let selector_used = match rln_system.parse_selector(&selector) {
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
    println!(
        "  list                                                            - List registered users"
    );
    println!(
        "  register                                                        - Register a new user"
    );
    println!("  send -u <index> -m <message_ids> --selector <bools> -s <signal> - Send a message with proof");
    println!("  (example: send -u 0 -m 0,1,2,3 --selector 1,1,0,0 -s \"hello\")");
    println!(
        "  clear                                                           - Clear the screen"
    );
    println!(
        "  exit                                                            - Exit the program"
    );
}
