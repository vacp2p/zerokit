use std::{hint::black_box, sync::LazyLock};

use criterion::{criterion_group, criterion_main, Criterion};
use rln::prelude::*;
use zerokit_utils::{
    hasher::ZerokitHasher,
    merkle_tree::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree},
};

static LEAVES: LazyLock<Vec<Fr>> = LazyLock::new(|| {
    let mut leaves = Vec::with_capacity(1 << 20);
    for i in 0..(1 << 20) {
        leaves.push(Fr::from(i as u64));
    }
    leaves
});

const LEAF_COUNT: usize = 8192;

fn tree_benchmark<P, P2>(c: &mut Criterion, tree_name: &str)
where
    P: ZerokitMerkleTree,
    P::Hasher: ZerokitHasher<Scalar = Fr>,
    <P::Proof as ZerokitMerkleProof>::Hasher: ZerokitHasher<Scalar = Fr>,
    P2: ZerokitMerkleTree,
    P2::Hasher: ZerokitHasher<Scalar = Fr>,
    <P2::Proof as ZerokitMerkleProof>::Hasher: ZerokitHasher<Scalar = Fr>,
{
    let mut tree = P::default(20).unwrap();
    let mut tree_poseidon2 = P2::default(20).unwrap();
    let mut verify_tree = P::default(20).unwrap();
    let mut verify_tree_poseidon2 = P2::default(20).unwrap();
    for i in 0..LEAF_COUNT {
        tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
        tree_poseidon2.set(i, LEAVES[i % LEAVES.len()]).unwrap();
        verify_tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
        verify_tree_poseidon2
            .set(i, LEAVES[i % LEAVES.len()])
            .unwrap();
    }

    let cached_leaf = LEAVES[0];
    let cached_proof = verify_tree.proof(0).unwrap();
    let cached_proof_poseidon2 = verify_tree_poseidon2.proof(0).unwrap();

    let mut update_next_tree = P::default(20).unwrap();
    let mut update_next_tree_poseidon2 = P2::default(20).unwrap();

    let mut group = c.benchmark_group(format!("{tree_name}::set"));
    group.bench_function("poseidon", |b| {
        let mut index = LEAF_COUNT;
        b.iter(|| {
            tree.set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });
    group.bench_function("poseidon2", |b| {
        let mut index = LEAF_COUNT;
        b.iter(|| {
            tree_poseidon2
                .set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });
    group.finish();

    let mut group = c.benchmark_group(format!("{tree_name}::set_range"));
    group.bench_function("poseidon", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.set_range(offset, LEAVES[range].iter().cloned())
                .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });
    group.bench_function("poseidon2", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree_poseidon2
                .set_range(offset, LEAVES[range].iter().cloned())
                .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });
    group.finish();

    let mut group = c.benchmark_group(format!("{tree_name}::update_next"));
    group.bench_function("poseidon", |b| {
        let mut next_value = 0;
        b.iter(|| {
            if update_next_tree.leaves_set() >= (1 << 20) {
                update_next_tree = P::default(20).unwrap();
            }
            update_next_tree
                .update_next(LEAVES[next_value % LEAVES.len()])
                .unwrap();
            next_value += 1;
        })
    });
    group.bench_function("poseidon2", |b| {
        let mut next_value = 0;
        b.iter(|| {
            if update_next_tree_poseidon2.leaves_set() >= (1 << 20) {
                update_next_tree_poseidon2 = P2::default(20).unwrap();
            }
            update_next_tree_poseidon2
                .update_next(LEAVES[next_value % LEAVES.len()])
                .unwrap();
            next_value += 1;
        })
    });
    group.finish();

    let mut group = c.benchmark_group(format!("{tree_name}::verify"));
    group.bench_function("poseidon", |b| {
        b.iter(|| {
            verify_tree.verify(&cached_leaf, &cached_proof).unwrap();
        })
    });
    group.bench_function("poseidon2", |b| {
        b.iter(|| {
            verify_tree_poseidon2
                .verify(&cached_leaf, &cached_proof_poseidon2)
                .unwrap();
        })
    });
    group.finish();

    let mut group = c.benchmark_group(format!("{tree_name}Proof::compute_root_from"));
    group.bench_function("poseidon", |b| {
        b.iter(|| {
            black_box(cached_proof.compute_root_from(&cached_leaf));
        })
    });
    group.bench_function("poseidon2", |b| {
        b.iter(|| {
            black_box(cached_proof_poseidon2.compute_root_from(&cached_leaf));
        })
    });
    group.finish();
}

pub fn poseidon_tree_benchmark(c: &mut Criterion) {
    tree_benchmark::<FullMerkleTree<PoseidonHash>, FullMerkleTree<Poseidon2Hash>>(
        c,
        "FullMerkleTree",
    );
    tree_benchmark::<OptimalMerkleTree<PoseidonHash>, OptimalMerkleTree<Poseidon2Hash>>(
        c,
        "OptimalMerkleTree",
    );
    tree_benchmark::<PmTree<SledDB, PoseidonHash>, PmTree<SledDB, Poseidon2Hash>>(c, "PmTree");
}

criterion_group!(benches, poseidon_tree_benchmark);
criterion_main!(benches);
