use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::ThreadRng, thread_rng};
use rln::prelude::*;
use zerokit_utils::merkle_tree::ZerokitMerkleTree;

fn get_test_witness() -> RLNWitnessInput {
    let leaf_index = 3;
    let identity_keys = IdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng());
    let user_message_limit = Fr::from(100);
    let rate_commitment =
        Hasher::<PoseidonHash>::hash_pair(identity_keys.id_commitment(), user_message_limit);

    let mut tree = PmTree::<SledDB, PoseidonHash>::default(DEFAULT_TREE_DEPTH).unwrap();
    tree.set(leaf_index, rate_commitment).unwrap();

    let merkle_proof = tree.proof(leaf_index).unwrap();

    let signal = b"hey hey";
    let x = hash_to_field_le(signal);

    let epoch = hash_to_field_le(b"test-epoch");
    let rln_identifier = hash_to_field_le(b"test-rln-identifier");
    let external_nullifier = Hasher::<PoseidonHash>::hash_pair(epoch, rln_identifier);

    let message_id = Fr::from(1);

    RLNWitnessInput::new_single()
        .identity_secret(identity_keys.identity_secret())
        .user_message_limit(user_message_limit)
        .merkle_proof(&merkle_proof)
        .x(x)
        .external_nullifier(external_nullifier)
        .message_id(message_id)
        .build()
        .unwrap()
}

pub fn generate_proof_benchmark(c: &mut Criterion) {
    let rln = RLNBuilder::stateless().build();

    let witness = get_test_witness();
    let partial_witness = RLNPartialWitnessInput::from(&witness);

    c.bench_function("RLN::generate_proof", |b| {
        b.iter(|| {
            let _ = rln.generate_proof(&witness).unwrap();
        })
    });

    c.bench_function("RLN::generate_partial_proof", |b| {
        b.iter(|| {
            let _ = rln.generate_partial_proof(&partial_witness).unwrap();
        })
    });

    let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();
    c.bench_function("RLN::finish_proof", |b| {
        b.iter(|| {
            let _ = rln.finish_proof(&partial_proof, &witness).unwrap();
        })
    });
}

criterion_group!(benches, generate_proof_benchmark);
criterion_main!(benches);
