use criterion::{criterion_group, criterion_main, Criterion};
use rln::prelude::*;
use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

fn get_test_witness() -> RLNWitnessInput {
    let leaf_index = 3;
    // Generate identity pair
    let (identity_secret, id_commitment) = keygen();
    let user_message_limit = Fr::from(100);
    let rate_commitment = poseidon_hash_pair(id_commitment, user_message_limit);

    // Generate merkle tree
    let mut tree = PmTree::default(DEFAULT_TREE_DEPTH).unwrap();
    tree.set(leaf_index, rate_commitment).unwrap();

    let merkle_proof = tree.proof(leaf_index).unwrap();

    let signal = b"hey hey";
    let x = hash_to_field_le(signal);

    // We set the remaining values to random ones
    let epoch = hash_to_field_le(b"test-epoch");
    let rln_identifier = hash_to_field_le(b"test-rln-identifier");
    let external_nullifier = poseidon_hash_pair(epoch, rln_identifier);

    let message_id = Fr::from(1);

    RLNWitnessInput::new_single()
        .identity_secret(identity_secret)
        .user_message_limit(user_message_limit)
        .path_elements(merkle_proof.get_path_elements())
        .identity_path_index(merkle_proof.get_path_index())
        .x(x)
        .external_nullifier(external_nullifier)
        .message_id(message_id)
        .build()
        .unwrap()
}

pub fn rln_proof_benchmark(c: &mut Criterion) {
    let rln = RLNBuilder::stateless().build();

    let witness = get_test_witness();
    let partial_witness = RLNPartialWitnessInput::from(&witness);

    c.bench_function("rln_generate_proof", |b| {
        b.iter(|| {
            let _ = rln.generate_proof(&witness).unwrap();
        })
    });

    c.bench_function("rln_generate_partial_proof", |b| {
        b.iter(|| {
            let _ = rln.generate_partial_proof(&partial_witness).unwrap();
        })
    });

    let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();
    c.bench_function("rln_finish_full_proof", |b| {
        b.iter(|| {
            let _ = rln.finish_proof(&partial_proof, &witness).unwrap();
        })
    });
}

criterion_group!(benches, rln_proof_benchmark);
criterion_main!(benches);
