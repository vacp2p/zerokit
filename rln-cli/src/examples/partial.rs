use std::{
    collections::{HashMap, VecDeque},
    io::{stdin, stdout, Write},
};

use clap::{Parser, Subcommand};
use rln::prelude::{
    default_graph_single, default_zkey_single, hash_to_field_le, keygen, poseidon_hash,
    ArkGroth16Backend, Fr, IdSecret, PartialProof, PoseidonHash, RLNBuilder,
    RLNPartialWitnessInputV3, RLNProofValuesV3, RLNWitnessInputV3, RecoverSecret, Stateful, RLNV3,
};
use zerokit_utils::merkle_tree::{FullMerkleTree, Hasher, ZerokitMerkleProof, ZerokitMerkleTree};

const MESSAGE_LIMIT: u32 = 1;

const TREE_DEPTH: usize = 20;

const ROOT_HISTORY_LIMIT: usize = 3;

const PARTIAL_REFRESH_INTERVAL: usize = ROOT_HISTORY_LIMIT;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
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
    Roots,
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

#[derive(Clone)]
struct CachedPartialProof {
    root: Fr,
    proof: PartialProof,
    path_elements: Vec<Fr>,
    path_index: Vec<u8>,
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
    rln: RLNV3<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend>,
    used_nullifiers: HashMap<Fr, RLNProofValuesV3>,
    local_identities: HashMap<usize, Identity>,
    partial_proofs: HashMap<usize, CachedPartialProof>,
    external_nullifier: Fr,
    latest_roots: VecDeque<Fr>,
    pending_registrations: usize,
}

impl RLNSystem {
    fn new(external_nullifier: Fr) -> Result<Self> {
        let full_merkle_tree: FullMerkleTree<PoseidonHash> = FullMerkleTree::new(
            TREE_DEPTH,
            PoseidonHash::default_leaf(),
            ConfigOf::<FullMerkleTree<PoseidonHash>>::default(),
        )?;
        let rln = RLNBuilder::stateful()
            .tree(full_merkle_tree)
            .graph(default_graph_single().clone())
            .zkey(default_zkey_single().clone())
            .build();

        let mut latest_roots = VecDeque::new();
        latest_roots.push_front(rln.get_root());
        println!("RLN instance initialized successfully");
        Ok(RLNSystem {
            rln,
            used_nullifiers: HashMap::new(),
            local_identities: HashMap::new(),
            partial_proofs: HashMap::new(),
            external_nullifier,
            latest_roots,
            pending_registrations: 0,
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

    fn list_roots(&self) {
        if self.latest_roots.is_empty() {
            println!("No roots recorded yet.");
            return;
        }

        println!("Latest roots (newest first, max {ROOT_HISTORY_LIMIT}):");
        for (i, root) in self.latest_roots.iter().enumerate() {
            println!("#{i}: {root}");
        }
    }

    fn record_root(&mut self) {
        let current_root = self.rln.get_root();
        if self.latest_roots.front() == Some(&current_root) {
            return;
        }
        self.latest_roots.push_front(current_root);
        while self.latest_roots.len() > ROOT_HISTORY_LIMIT {
            self.latest_roots.pop_back();
        }
    }

    fn root_is_recent(&self, root: &Fr) -> bool {
        self.latest_roots.iter().any(|r| r == root)
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
                self.record_root();
                self.pending_registrations += 1;
                if self.pending_registrations >= PARTIAL_REFRESH_INTERVAL {
                    self.rebuild_partial_proofs()?;
                    self.pending_registrations = 0;
                    println!(
                        "Refreshed partial proofs after {PARTIAL_REFRESH_INTERVAL} registrations"
                    );
                } else {
                    let remaining = PARTIAL_REFRESH_INTERVAL - self.pending_registrations;
                    println!(
                        "Skipping partial proof refresh: {remaining} more registration(s) before next refresh"
                    );
                }
            }
            Err(_) => {
                println!("Maximum user limit reached: 2^{TREE_DEPTH}");
            }
        };

        Ok(index)
    }

    fn rebuild_partial_proofs(&mut self) -> Result<()> {
        let indices: Vec<usize> = self.local_identities.keys().copied().collect();
        let current_root = self.rln.get_root();
        self.partial_proofs.clear();
        for user_index in indices {
            let identity = &self.local_identities[&user_index];
            let merkle_proof = self.rln.get_merkle_proof(user_index)?;
            let witness = RLNWitnessInputV3::new_single()
                .identity_secret(identity.identity_secret.clone())
                .user_message_limit(Fr::from(MESSAGE_LIMIT))
                .path_elements(merkle_proof.get_path_elements())
                .identity_path_index(merkle_proof.get_path_index())
                .x(Fr::from(0u64))
                .external_nullifier(self.external_nullifier)
                .message_id(Fr::from(0u64))
                .build()?;
            let partial_witness = RLNPartialWitnessInputV3::from(&witness);
            let partial_proof = self.rln.generate_partial_proof(&partial_witness)?;
            self.partial_proofs.insert(
                user_index,
                CachedPartialProof {
                    root: current_root,
                    proof: partial_proof,
                    path_elements: merkle_proof.get_path_elements(),
                    path_index: merkle_proof.get_path_index(),
                },
            );
            println!("Pre-generated partial proof for user: {user_index}");
        }
        Ok(())
    }

    fn generate_and_verify_proof(
        &mut self,
        user_index: usize,
        message_id: u32,
        signal: &str,
        external_nullifier: Fr,
    ) -> Result<RLNProofValuesV3> {
        let identity = match self.local_identities.get(&user_index) {
            Some(identity) => identity,
            None => return Err(format!("User {user_index} not found").into()),
        };

        let x = hash_to_field_le(signal.as_bytes());
        let current_root = self.rln.get_root();

        let cache_is_fresh = matches!(
            self.partial_proofs.get(&user_index),
            Some(cached) if self.root_is_recent(&cached.root)
        );
        if cache_is_fresh {
            println!("Using cached partial proof for user {user_index}");
        } else {
            println!(
                "Cached partial proof missing or stale for user {user_index}; generating fresh proof"
            );
            let merkle_proof = self.rln.get_merkle_proof(user_index)?;
            let partial_witness = RLNPartialWitnessInputV3::new()
                .identity_secret(identity.identity_secret.clone())
                .user_message_limit(Fr::from(MESSAGE_LIMIT))
                .path_elements(merkle_proof.get_path_elements())
                .identity_path_index(merkle_proof.get_path_index())
                .build()?;
            let generated = self.rln.generate_partial_proof(&partial_witness)?;
            self.partial_proofs.insert(
                user_index,
                CachedPartialProof {
                    root: current_root,
                    proof: generated,
                    path_elements: merkle_proof.get_path_elements(),
                    path_index: merkle_proof.get_path_index(),
                },
            );
        }

        let cached = &self.partial_proofs[&user_index];
        let witness = RLNWitnessInputV3::new_single()
            .identity_secret(identity.identity_secret.clone())
            .user_message_limit(Fr::from(MESSAGE_LIMIT))
            .path_elements(cached.path_elements.clone())
            .identity_path_index(cached.path_index.clone())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(message_id))
            .build()?;

        let (proof, proof_values) = self.rln.finish_proof(&cached.proof, &witness)?;
        println!("Proof generated successfully:");
        println!("+ User: {user_index}");
        println!("+ Message ID: {message_id}");
        println!("+ Signal: {signal}");

        let verified = self.rln.verify_with_roots(
            &proof,
            &proof_values,
            &x,
            self.latest_roots.make_contiguous(),
        )?;
        if verified {
            println!("Proof verified successfully");
        }

        Ok(proof_values)
    }

    fn check_nullifier(&mut self, proof_values: RLNProofValuesV3) -> Result<()> {
        if let Some(nullifier) = proof_values.nullifier() {
            if let Some(previous_proof_values) = self.used_nullifiers.get(&nullifier).cloned() {
                self.handle_duplicate_nullifier(&previous_proof_values, &proof_values)?;
                return Ok(());
            }

            self.used_nullifiers.insert(nullifier, proof_values);
            println!("Message verified and accepted");
        }

        Ok(())
    }

    fn handle_duplicate_nullifier(
        &mut self,
        previous_proof_values: &RLNProofValuesV3,
        current_proof_values: &RLNProofValuesV3,
    ) -> Result<()> {
        if previous_proof_values.x() == current_proof_values.x()
            && previous_proof_values.y() == current_proof_values.y()
        {
            return Err("this exact message and signal has already been sent".into());
        }

        match previous_proof_values.recover_secret(current_proof_values) {
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
                        self.record_root();
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
    println!("Initializing RLN instance...");
    print!("\x1B[2J\x1B[1;1H");
    let rln_epoch = hash_to_field_le(b"epoch");
    let rln_identifier = hash_to_field_le(b"rln-identifier");
    let external_nullifier = poseidon_hash(&[rln_epoch, rln_identifier]);
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
                Commands::Roots => {
                    rln_system.list_roots();
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
    println!("  roots                                       - Show latest 3 recorded roots");
    println!("  register                                    - Register a new user");
    println!("  send -u <index> -m <message_id> -s <signal> - Send a message with partial proof");
    println!("  (example: send -u 0 -m 0 -s \"hello\")");
    println!("  clear                                       - Clear the screen");
    println!("  exit                                        - Exit the program");
}
