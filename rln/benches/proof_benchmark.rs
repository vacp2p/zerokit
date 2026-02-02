use criterion::{criterion_group, criterion_main, Criterion};
use rln::prelude::*;
use rln::protocol::generate_zk_proof_icicle;
use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

fn get_test_witness() -> RLNWitnessInput {
    let leaf_index = 3;
    let (identity_secret, id_commitment) = keygen().unwrap();
    let user_message_limit = Fr::from(100);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

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

fn proof_generation_benchmark(c: &mut Criterion) {
    let witness = get_test_witness();
    let proving_key = zkey_from_folder();
    let graph_data = graph_from_folder();

    let mut group = c.benchmark_group("proof_generation");

    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    group.bench_function("standard", |b| {
        b.iter(|| {
            let _ = generate_zk_proof(proving_key, &witness, graph_data).unwrap();
        })
    });

    group.finish();
}

fn proof_generation_icicle_benchmark(c: &mut Criterion) {
    // let _ = init_icicle_backend();

    let witness = get_test_witness();
    let proving_key = zkey_from_folder();
    let graph_data = graph_from_folder();

    let mut group = c.benchmark_group("proof_generation_icicle");

    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    group.bench_function("icicle", |b| {
        b.iter(|| {
            let _ = generate_zk_proof_icicle(proving_key, &witness, graph_data).unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    proof_generation_benchmark,
    proof_generation_icicle_benchmark
);

criterion_main!(benches);
