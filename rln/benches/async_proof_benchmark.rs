use std::{thread::available_parallelism, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rln::prelude::*;
#[cfg(feature = "icicle")]
use rln::protocol::generate_zk_proof_icicle;
use tokio::{runtime::Builder, task::JoinSet};
use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

fn get_proof_count() -> usize {
    available_parallelism().map(|p| p.get() * 2).unwrap_or(8)
}

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

fn async_proof_generation_benchmark(c: &mut Criterion) {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();

    let witness = get_test_witness();
    let proof_count = get_proof_count();

    let mut group = c.benchmark_group("async_proof_generation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.throughput(Throughput::Elements(proof_count as u64));

    group.bench_function("standard", |b| {
        b.to_async(&rt).iter(|| async {
            let mut set = JoinSet::new();
            for _ in 0..proof_count {
                let witness = witness.clone();
                set.spawn_blocking(move || {
                    let proving_key = zkey_from_folder();
                    let graph_data = graph_from_folder();
                    generate_zk_proof(proving_key, &witness, graph_data).unwrap()
                });
            }
            set.join_all().await
        });
    });

    group.finish();
}

fn async_proof_generation_icicle_benchmark(c: &mut Criterion) {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();

    let witness = get_test_witness();
    let proof_count = get_proof_count();

    let mut group = c.benchmark_group("async_proof_generation_icicle");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.throughput(Throughput::Elements(proof_count as u64));

    group.bench_function("icicle", |b| {
        b.to_async(&rt).iter(|| async {
            let mut set = JoinSet::new();
            for _ in 0..proof_count {
                let witness = witness.clone();
                set.spawn_blocking(move || {
                    let proving_key = zkey_from_folder();
                    let graph_data = graph_from_folder();
                    generate_zk_proof_icicle(proving_key, &witness, graph_data).unwrap()
                });
            }
            set.join_all().await
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    async_proof_generation_benchmark,
    async_proof_generation_icicle_benchmark
);

criterion_main!(benches);
