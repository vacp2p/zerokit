use rln::prelude::*;
use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};
use criterion::{criterion_group, criterion_main, Criterion};

type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;


fn get_test_witness() -> RLNWitnessInput {
    let leaf_index = 3;
    // Generate identity pair
    let (identity_secret, id_commitment) = keygen().unwrap();
    let user_message_limit = Fr::from(100);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

    //// generate merkle tree
    let default_leaf = Fr::from(0);
    let mut tree = PoseidonTree::new(
        DEFAULT_TREE_DEPTH,
        default_leaf,
        ConfigOf::<PoseidonTree>::default(),
    )
        .unwrap();
    tree.set(leaf_index, rate_commitment).unwrap();

    let merkle_proof = tree.proof(leaf_index).unwrap();

    let signal = b"hey hey";
    let x = hash_to_field_le(signal).unwrap();

    // We set the remaining values to random ones
    let epoch = hash_to_field_le(b"test-epoch").unwrap();
    let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

    let message_id = Fr::from(1);

    RLNWitnessInput::new(
        identity_secret,
        user_message_limit,
        message_id,
        merkle_proof.get_path_elements(),
        merkle_proof.get_path_index(),
        x,
        external_nullifier,
    )
        .unwrap()
}

fn get_partial_witness(witness: &RLNWitnessInput) -> RLNPartialWitnessInput {
    RLNPartialWitnessInput::new(
        witness.identity_secret().clone(),
        *witness.user_message_limit(),
        witness.path_elements().to_vec(),
        witness.identity_path_index().to_vec(),
    )
    .unwrap()
}

pub fn rln_proof_benchmark(c: &mut Criterion) {
    let witness = get_test_witness();
    let partial_witness = get_partial_witness(&witness);

    let proving_key = zkey_from_folder();
    let graph_data = graph_from_folder();

    c.bench_function("rln_full_proof", |b| {
        b.iter(|| {
            let _ = generate_zk_proof(proving_key, &witness, graph_data).unwrap();
        })
    });

    c.bench_function("rln_partial_proof_generation", |b| {
        b.iter(|| {
            let _ = generate_partial_zk_proof(proving_key, &partial_witness, graph_data).unwrap();
        })
    });

    let partial_proof = generate_partial_zk_proof(proving_key, &partial_witness, graph_data).unwrap();
    c.bench_function("rln_finish_partial_proof", |b| {
        b.iter(|| {
            let _ = finish_zk_proof(proving_key, &partial_proof, &witness, graph_data)
                .unwrap();
        })
    });
}

criterion_group!(benches, rln_proof_benchmark);
criterion_main!(benches);