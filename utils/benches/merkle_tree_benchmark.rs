use std::{hint::black_box, sync::LazyLock};

use criterion::{criterion_group, criterion_main, Criterion};
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::merkle_tree::{
    FullMerkleConfig, FullMerkleTree, OptimalMerkleConfig, OptimalMerkleTree, ZerokitHasher,
    ZerokitMerkleProof, ZerokitMerkleTree,
};

#[derive(Clone, Copy, PartialEq)]
struct Keccak256;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct TestFr([u8; 32]);

impl ZerokitHasher for Keccak256 {
    type Scalar = TestFr;

    fn hash(input: &[Self::Scalar]) -> Self::Scalar {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for fr in input {
            hasher.update(fr.0.as_slice());
        }
        hasher.finalize(&mut output);
        TestFr(output)
    }
}

static LEAVES: LazyLock<Vec<TestFr>> = LazyLock::new(|| {
    let mut leaves = Vec::with_capacity(1 << 20);
    for i in 0..(1 << 20) {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&(i as u32).to_be_bytes());
        leaves.push(TestFr(bytes));
    }
    leaves
});

static INDICES: LazyLock<Vec<usize>> = LazyLock::new(|| (0..(1 << 20)).collect());

const LEAF_COUNT: usize = 8192;

pub fn optimal_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        OptimalMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap();

    for i in 0..LEAF_COUNT {
        tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    let mut verify_tree =
        OptimalMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap();
    for i in 0..LEAF_COUNT {
        verify_tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    let cached_leaf_index = 0;
    let cached_leaf = LEAVES[cached_leaf_index];
    let cached_proof = verify_tree.proof(cached_leaf_index).unwrap();

    let mut update_next_tree =
        OptimalMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap();

    c.bench_function("OptimalMerkleTree::get_subtree_root", |b| {
        let mut level = 1;
        let mut index = 0;
        b.iter(|| {
            tree.get_subtree_root(level % 20, index % (1 << (20 - (level % 20))))
                .unwrap();
            index = (index + 1) % (1 << (20 - (level % 20)));
            level = 1 + (level % 20);
        })
    });

    c.bench_function("OptimalMerkleTree::set", |b| {
        let mut index = LEAF_COUNT;
        b.iter(|| {
            tree.set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });

    c.bench_function("OptimalMerkleTree::set_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.set_range(offset, LEAVES[range].iter().cloned())
                .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });

    c.bench_function("OptimalMerkleTree::get", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.get(index % LEAF_COUNT).unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("OptimalMerkleTree::get_empty_leaves_indices", |b| {
        b.iter(|| {
            tree.get_empty_leaves_indices();
        })
    });

    c.bench_function("OptimalMerkleTree::override_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.override_range(
                offset,
                LEAVES[range.clone()].iter().cloned(),
                INDICES[range.clone()].iter().cloned(),
            )
            .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });

    c.bench_function("OptimalMerkleTree::update_next", |b| {
        let mut next_value = 0;
        b.iter(|| {
            if update_next_tree.leaves_set() >= (1 << 20) {
                update_next_tree = OptimalMerkleTree::<Keccak256>::new(
                    20,
                    TestFr([0; 32]),
                    OptimalMerkleConfig::default(),
                )
                .unwrap();
            }
            update_next_tree
                .update_next(LEAVES[next_value % LEAVES.len()])
                .unwrap();
            next_value += 1;
        })
    });

    c.bench_function("OptimalMerkleTree::delete", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.delete(index % LEAF_COUNT).unwrap();
            tree.set(index % LEAF_COUNT, LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("OptimalMerkleTree::proof", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.proof(index % LEAF_COUNT).unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("OptimalMerkleTree::verify", |b| {
        b.iter(|| {
            verify_tree.verify(&cached_leaf, &cached_proof).unwrap();
        })
    });

    c.bench_function("OptimalMerkleProof::compute_root_from", |b| {
        b.iter(|| {
            black_box(cached_proof.compute_root_from(&cached_leaf));
        })
    });
}

pub fn full_merkle_tree_benchmark(c: &mut Criterion) {
    let mut tree =
        FullMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), FullMerkleConfig::default()).unwrap();

    for i in 0..LEAF_COUNT {
        tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    let mut verify_tree =
        FullMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), FullMerkleConfig::default()).unwrap();
    for i in 0..LEAF_COUNT {
        verify_tree.set(i, LEAVES[i % LEAVES.len()]).unwrap();
    }

    let cached_leaf_index = 0;
    let cached_leaf = LEAVES[cached_leaf_index];
    let cached_proof = verify_tree.proof(cached_leaf_index).unwrap();

    let mut update_next_tree =
        FullMerkleTree::<Keccak256>::new(20, TestFr([0; 32]), FullMerkleConfig::default()).unwrap();

    c.bench_function("FullMerkleTree::get_subtree_root", |b| {
        let mut level = 1;
        let mut index = 0;
        b.iter(|| {
            tree.get_subtree_root(level % 20, index % (1 << (20 - (level % 20))))
                .unwrap();
            index = (index + 1) % (1 << (20 - (level % 20)));
            level = 1 + (level % 20);
        })
    });

    c.bench_function("FullMerkleTree::set", |b| {
        let mut index = LEAF_COUNT;
        b.iter(|| {
            tree.set(index % (1 << 20), LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % (1 << 20);
        })
    });

    c.bench_function("FullMerkleTree::set_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.set_range(offset, LEAVES[range].iter().cloned())
                .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });

    c.bench_function("FullMerkleTree::get", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.get(index % LEAF_COUNT).unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("FullMerkleTree::get_empty_leaves_indices", |b| {
        b.iter(|| {
            tree.get_empty_leaves_indices();
        })
    });

    c.bench_function("FullMerkleTree::override_range", |b| {
        let mut offset = 0;
        b.iter(|| {
            let range = offset..offset + LEAF_COUNT;
            tree.override_range(
                offset,
                LEAVES[range.clone()].iter().cloned(),
                INDICES[range.clone()].iter().cloned(),
            )
            .unwrap();
            offset = (offset + LEAF_COUNT) % (1 << 20);
        })
    });

    c.bench_function("FullMerkleTree::update_next", |b| {
        let mut next_value = 0;
        b.iter(|| {
            if update_next_tree.leaves_set() >= (1 << 20) {
                update_next_tree = FullMerkleTree::<Keccak256>::new(
                    20,
                    TestFr([0; 32]),
                    FullMerkleConfig::default(),
                )
                .unwrap();
            }
            update_next_tree
                .update_next(LEAVES[next_value % LEAVES.len()])
                .unwrap();
            next_value += 1;
        })
    });

    c.bench_function("FullMerkleTree::delete", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.delete(index % LEAF_COUNT).unwrap();
            tree.set(index % LEAF_COUNT, LEAVES[index % LEAVES.len()])
                .unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("FullMerkleTree::proof", |b| {
        let mut index = 0;
        b.iter(|| {
            tree.proof(index % LEAF_COUNT).unwrap();
            index = (index + 1) % LEAF_COUNT;
        })
    });

    c.bench_function("FullMerkleTree::verify", |b| {
        b.iter(|| {
            verify_tree.verify(&cached_leaf, &cached_proof).unwrap();
        })
    });

    c.bench_function("FullMerkleProof::compute_root_from", |b| {
        b.iter(|| {
            black_box(cached_proof.compute_root_from(&cached_leaf));
        })
    });
}

criterion_group!(
    benches,
    optimal_merkle_tree_benchmark,
    full_merkle_tree_benchmark,
);
criterion_main!(benches);
