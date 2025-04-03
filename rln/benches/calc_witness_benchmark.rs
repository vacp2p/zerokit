use std::time::Duration;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

use rln::circuit::{calc_witness_2, calculate_rln_witness, graph_from_folder, zkey_from_folder, Fr, TEST_TREE_HEIGHT};
use rln::hashers::{hash_to_field, poseidon_hash};
use rln::iden3calc::calc_witness;
use rln::poseidon_tree::PoseidonTree;
use rln::protocol::{inputs_for_witness_calculation, keygen, rln_witness_from_json, rln_witness_from_values, rln_witness_to_json, RLNWitnessInput};
use utils::ZerokitMerkleTree;

type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

fn get_test_witness() -> RLNWitnessInput {
    let leaf_index = 3;
    // Generate identity pair
    let (identity_secret_hash, id_commitment) = keygen();
    let user_message_limit = Fr::from(100);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);

    //// generate merkle tree
    let default_leaf = Fr::from(0);
    let mut tree = PoseidonTree::new(
        TEST_TREE_HEIGHT,
        default_leaf,
        ConfigOf::<PoseidonTree>::default(),
    )
        .unwrap();
    tree.set(leaf_index, rate_commitment.into()).unwrap();

    let merkle_proof = tree.proof(leaf_index).expect("proof should exist");

    let signal = b"hey hey";
    let x = hash_to_field(signal);

    // We set the remaining values to random ones
    let epoch = hash_to_field(b"test-epoch");
    let rln_identifier = hash_to_field(b"test-rln-identifier");
    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

    rln_witness_from_values(
        identity_secret_hash,
        &merkle_proof,
        x,
        external_nullifier,
        user_message_limit,
        Fr::from(1),
    )
        .unwrap()
}

fn bench_calc_witness(c: &mut Criterion) {

    // We generate all relevant keys
    let proving_key = zkey_from_folder();
    // let verification_key = &proving_key.0.vk;
    let graph_data = graph_from_folder();
    // We compute witness from the json input
    let rln_witness = get_test_witness();
    let rln_witness_json = rln_witness_to_json(&rln_witness).unwrap();
    // let rln_witness_deser = rln_witness_from_json(rln_witness_json).unwrap();

    let inputs_1 = inputs_for_witness_calculation(&rln_witness)
        .unwrap()
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));
    let inputs_2 = inputs_for_witness_calculation(&rln_witness)
        .unwrap()
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let mut group = c.benchmark_group("calc_witness");
    // group.sample_size(50);
    group.measurement_time(Duration::from_secs(11));
    group.bench_function("Circom-witnesscalc current", |b| b.iter(|| calc_witness(inputs_1.clone(), graph_data) ));
    // group.bench_function("Circom-witnesscalc crate(git)", |b| b.iter(|| calculate_rln_witness(inputs, graph_data) ));
    group.bench_function("Circom-witnesscalc crate(git)", |b| b.iter(|| calc_witness_2(inputs_2.clone(), graph_data) ));
    
    group.finish();
}

criterion_group!(benches, bench_calc_witness);
criterion_main!(benches);

